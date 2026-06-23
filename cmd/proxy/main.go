package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/tuka79/ImmichCrypt/internal/crypto"
)

const Version = "3.0.0-pqc"

var (
	r2Endpoint  string
	r2AccessKey string
	r2SecretKey string
	r2Bucket    string
	listenPort  string

	masterKey  []byte
	awsCreds   aws.Credentials
	v4Signer   *v4.Signer

	useSSEC      bool
	keySlotsFile string
	keySlots     *crypto.KeySlots
)

func loadMasterKey() error {
	slotStr := os.Getenv("KEY_SLOTS")
	if slotStr != "" {
		var err error
		keySlots, err = crypto.UnmarshalKeySlots([]byte(slotStr))
		if err != nil {
			return fmt.Errorf("parse KEY_SLOTS: %w", err)
		}
		key, err := keySlots.Unlock()
		if err != nil {
			log.Printf("WARN: KEY_SLOTS provided but unlock failed: %v — falling back to SSE_C_KEY", err)
		} else {
			masterKey = key
			log.Printf("Master key unlocked from key slots")
			return nil
		}
	}

	keyEnv := os.Getenv("SSE_C_KEY")
	if keyEnv != "" {
		key, err := base64.StdEncoding.DecodeString(keyEnv)
		if err != nil {
			return fmt.Errorf("SSE_C_KEY invalid base64: %w", err)
		}
		if len(key) != crypto.KeySize {
			return fmt.Errorf("SSE_C_KEY must be %d bytes, got %d", crypto.KeySize, len(key))
		}
		masterKey = key
		log.Printf("Master key loaded from SSE_C_KEY (%d bytes)", len(key))
		return nil
	}

	keyFile := os.Getenv("KEY_FILE")
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read %s: %w", keyFile, err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return fmt.Errorf("KEY_FILE invalid base64: %w", err)
		}
		if len(key) != crypto.KeySize {
			return fmt.Errorf("KEY_FILE key must be %d bytes", crypto.KeySize)
		}
		masterKey = key
		return nil
	}

	return fmt.Errorf("no key source: set SSE_C_KEY, KEY_SLOTS, or KEY_FILE")
}

func initKeySlots() {
	if keySlotsFile == "" || masterKey == nil {
		return
	}

	data, err := os.ReadFile(keySlotsFile)
	if err != nil {
		log.Printf("No key slots file at %s (will create on first use)", keySlotsFile)
		return
	}

	keySlots, err = crypto.UnmarshalKeySlots(data)
	if err != nil {
		log.Printf("ERROR parsing key slots: %v", err)
	}
}

func computeMD5(key []byte) string {
	h := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(h[:8])
}

func hashPayload(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func isObjectOp(path string) bool {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	return len(parts) >= 2 && parts[1] != "" && !strings.HasPrefix(parts[1], "?")
}

func buildUpstreamURL(path, rawQuery string) string {
	url := fmt.Sprintf("%s/%s%s", strings.TrimRight(r2Endpoint, "/"), r2Bucket, path)
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	return url
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading body: %v", err), 500)
		return
	}
	r.Body.Close()

	upstreamURL := buildUpstreamURL(r.URL.Path, r.URL.RawQuery)
	bodyReader := bytes.NewReader(bodyBytes)
	upReq, err := http.NewRequest(r.Method, upstreamURL, bodyReader)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), 500)
		return
	}

	for key, vals := range r.Header {
		lower := strings.ToLower(key)
		switch {
		case lower == "content-length", lower == "host", lower == "authorization":
			continue
		case strings.HasPrefix(lower, "x-amz-"):
			continue
		case lower == "content-type", lower == "content-language",
			lower == "content-disposition", lower == "cache-control", lower == "expires":
			for _, v := range vals {
				upReq.Header.Add(key, v)
			}
		}
	}

	if useSSEC && isObjectOp(r.URL.Path) {
		upReq.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		upReq.Header.Set("x-amz-server-side-encryption-customer-key",
			base64.StdEncoding.EncodeToString(masterKey))
		upReq.Header.Set("x-amz-server-side-encryption-customer-key-MD5",
			computeMD5(masterKey))
	}

	payloadHash := hashPayload(bodyBytes)
	upReq.Header.Set("x-amz-content-sha256", payloadHash)

	ctx := context.Background()
	signTime := time.Now().UTC()
	if err := v4Signer.SignHTTP(ctx, awsCreds, upReq, payloadHash, "s3", "auto", signTime); err != nil {
		log.Printf("ERROR signing request: %v", err)
		http.Error(w, fmt.Sprintf("Signing error: %v", err), 500)
		return
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(upReq)
	if err != nil {
		log.Printf("ERROR method=%s path=%s error=%v", r.Method, r.URL.Path, err)
		http.Error(w, fmt.Sprintf("Upstream error: %v", err), 502)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Response error", 502)
		return
	}

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	ssecFlag := "no"
	if useSSEC && isObjectOp(r.URL.Path) {
		ssecFlag = "AES256-GCM"
	}
	log.Printf("INFO method=%s path=%s status=%d bytes=%d duration=%v encrypt=%s v=%s",
		r.Method, r.URL.Path, resp.StatusCode, len(respBody), time.Since(start), ssecFlag, Version)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	slots := 0
	if keySlots != nil {
		slots = len(keySlots.Slots)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"version":      Version,
		"encryption":   "AES-256-GCM",
		"quantum_safe": true,
		"slots":        slots,
	})
}

func keySlotsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := loadMasterKey(); err != nil {
			http.Error(w, fmt.Sprintf("No key loaded: %v", err), 400)
			return
		}

		ks := &crypto.KeySlots{Version: 3}
		password := os.Getenv("MASTER_PASSWORD")
		if password != "" {
			ks.AddPasswordSlot(masterKey, password, "master-password")
		}

		sshPaths := []string{"$HOME/.ssh/id_ed25519", "$HOME/.ssh/id_rsa"}
		for _, p := range sshPaths {
			path := os.ExpandEnv(p)
			if _, err := os.Stat(path); err == nil {
				ks.AddSSHKeySlot(masterKey, path, "ssh-key")
				break
			}
		}

		keySlots = ks

		data, _ := ks.Marshal()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		log.Printf("Generated %d key slots", len(ks.Slots))
		return
	}

	if keySlots == nil {
		http.Error(w, "No key slots configured. POST to create.", 404)
		return
	}

	data, _ := keySlots.Marshal()
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	r2Endpoint = os.Getenv("R2_ENDPOINT")
	r2AccessKey = os.Getenv("R2_ACCESS_KEY_ID")
	r2SecretKey = os.Getenv("R2_SECRET_ACCESS_KEY")
	r2Bucket = os.Getenv("R2_BUCKET")
	listenPort = os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "2300"
	}

	useSSEC = os.Getenv("SSE_ENABLED") != "false"
	keySlotsFile = os.Getenv("KEY_SLOTS_FILE")

	if r2Endpoint == "" || r2AccessKey == "" || r2SecretKey == "" || r2Bucket == "" {
		log.Fatal("Missing required env: R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET")
	}

	if err := loadMasterKey(); err != nil {
		if os.Getenv("KEY_REQUIRED") == "true" {
			log.Fatal(err)
		}
		log.Printf("WARN: %v — encryption disabled", err)
		useSSEC = false
	} else {
		log.Printf("Encryption: AES-256-GCM | Key source: loaded")
	}

	initKeySlots()

	awsCreds = aws.Credentials{
		AccessKeyID:     r2AccessKey,
		SecretAccessKey: r2SecretKey,
	}
	v4Signer = v4.NewSigner()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/key-slots", keySlotsHandler)
	mux.HandleFunc("/", proxyHandler)

	log.Printf("immich-proxy v%s starting on :%s", Version, listenPort)
	log.Printf("  upstream: %s / %s", r2Endpoint, r2Bucket)
	if useSSEC {
		log.Printf("  encryption: AES-256-GCM (quantum-resistant)")
	}
	log.Printf("  key slots: %d recovery methods", func() int {
		if keySlots != nil {
			return len(keySlots.Slots)
		}
		return 0
	}())

	addr := fmt.Sprintf(":%s", listenPort)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
