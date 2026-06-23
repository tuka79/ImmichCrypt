package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// SlotType identifies which recovery method encrypted a key slot.
type SlotType string

const (
	SlotPassword SlotType = "password"
	SlotSSHKey   SlotType = "ssh-key"
	SlotYubiKey  SlotType = "yubikey"
	SlotShamir   SlotType = "shamir"
	SlotPasskey  SlotType = "passkey"
)

// KeySlot holds one encrypted copy of the master key.
// Multiple slots = multiple ways to recover.
type KeySlot struct {
	Type        SlotType `json:"type"`
	Label       string   `json:"label"`
	Encrypted   string   `json:"encrypted"`
	Salt        string   `json:"salt,omitempty"`
	Nonce       string   `json:"nonce,omitempty"` // for SSH slot: ed25519 nonce
}

// KeySlots is a LUKS-style key slot header stored alongside encrypted data.
type KeySlots struct {
	Version int       `json:"version"`
	Slots   []KeySlot `json:"slots"`
}

// AddPasswordSlot encrypts the master key with a password using Argon2id.
func (ks *KeySlots) AddPasswordSlot(masterKey []byte, password string, label string) error {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	derivedKey := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, KeySize)

	encrypted, err := Encrypt(derivedKey, masterKey)
	if err != nil {
		return err
	}

	ks.Slots = append(ks.Slots, KeySlot{
		Type:      SlotPassword,
		Label:     label,
		Encrypted: encrypted,
		Salt:      base64.StdEncoding.EncodeToString(salt),
	})

	return nil
}

// AddSSHKeySlot encrypts the master key with an SSH Ed25519 private key.
// The key is used as an HMAC-like wrapper: SHA256(key) derived, then as AES key.
func (ks *KeySlots) AddSSHKeySlot(masterKey []byte, sshKeyPath string, label string) error {
	keyData, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return fmt.Errorf("read ssh key: %w", err)
	}

	keyStr := strings.TrimSpace(string(keyData))
	keyHash := sha256.Sum256([]byte(keyStr))
	wrappingKey := keyHash[:]

	encrypted, err := Encrypt(wrappingKey, masterKey)
	if err != nil {
		return err
	}

	ks.Slots = append(ks.Slots, KeySlot{
		Type:      SlotSSHKey,
		Label:     label,
		Encrypted: encrypted,
	})

	return nil
}

// AddYubiKeySlot wraps the master key such that a YubiKey FIDO2 HMAC challenge
// can unlock it. The actual challenge-response happens at unlock time.
// For now, stores metadata for future FIDO2 integration.
func (ks *KeySlots) AddYubiKeySlot(masterKey []byte, label string) error {
	if len(masterKey) != KeySize {
		return ErrKeySize
	}

	ks.Slots = append(ks.Slots, KeySlot{
		Type:  SlotYubiKey,
		Label: label,
	})

	return nil
}

// AddShamirSlot stores references to Shamir shares (the actual shares are
// distributed via email). This slot stores verification hashes.
func (ks *KeySlots) AddShamirSlot(masterKey []byte, totalShares, threshold int, label string) error {
	shamirHash := sha256.Sum256(masterKey)

	ks.Slots = append(ks.Slots, KeySlot{
		Type:      SlotShamir,
		Label:     label,
		Encrypted: base64.StdEncoding.EncodeToString(shamirHash[:]),
	})

	return nil
}

// Unlock tries to recover the master key using an SSH key.
func (ks *KeySlots) UnlockWithSSHKey(sshKeyPath string) ([]byte, error) {
	keyData, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key: %w", err)
	}

	keyHash := sha256.Sum256([]byte(strings.TrimSpace(string(keyData))))

	for _, slot := range ks.Slots {
		if slot.Type == SlotSSHKey {
			masterKey, err := Decrypt(keyHash[:], slot.Encrypted)
			if err == nil {
				return masterKey, nil
			}
		}
	}

	return nil, errors.New("no matching SSH key slot found or decryption failed")
}

// UnlockWithPassword tries to recover the master key using a password.
func (ks *KeySlots) UnlockWithPassword(password string) ([]byte, error) {
	for _, slot := range ks.Slots {
		if slot.Type == SlotPassword {
			salt, err := base64.StdEncoding.DecodeString(slot.Salt)
			if err != nil {
				continue
			}

			derivedKey := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, KeySize)

			masterKey, err := Decrypt(derivedKey, slot.Encrypted)
			if err == nil {
				return masterKey, nil
			}
		}
	}

	return nil, errors.New("no matching password slot found or decryption failed")
}

// Unlock tries all available slots automatically.
// Priority: SSH key → password → yubikey (future)
func (ks *KeySlots) Unlock() ([]byte, error) {
	sshPaths := []string{
		os.ExpandEnv("$HOME/.ssh/id_ed25519"),
		os.ExpandEnv("$HOME/.ssh/id_rsa"),
	}

	for _, path := range sshPaths {
		if _, err := os.Stat(path); err == nil {
			if key, err := ks.UnlockWithSSHKey(path); err == nil {
				return key, nil
			}
		}
	}

	if pass := os.Getenv("MASTER_PASSWORD"); pass != "" {
		if key, err := ks.UnlockWithPassword(pass); err == nil {
			return key, nil
		}
	}

	if keyEnv := os.Getenv("SSE_C_KEY"); keyEnv != "" {
		key, err := base64.StdEncoding.DecodeString(keyEnv)
		if err == nil && len(key) == KeySize {
			return key, nil
		}
	}

	return nil, errors.New("no unlock method succeeded: checked SSH keys, MASTER_PASSWORD, SSE_C_KEY")
}

// Marshal converts to JSON for storage.
func (ks *KeySlots) Marshal() ([]byte, error) {
	return json.Marshal(ks)
}

// UnmarshalKeySlots parses from JSON.
func UnmarshalKeySlots(data []byte) (*KeySlots, error) {
	var ks KeySlots
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// ensure ed25519 imported (for future use)
var _ = ed25519.GenerateKey
