package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrKeySize   = errors.New("master key must be 32 bytes (AES-256)")
	ErrDecrypt   = errors.New("decryption failed: wrong key or corrupted data")
	ErrTooShort  = errors.New("ciphertext too short")
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

// GenerateMasterKey creates a new random 32-byte AES-256 key.
// Call this ONCE. Save in Bitwarden. Never store in plaintext.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// GenerateMasterKeyBase64 returns a base64-encoded key for env vars.
func GenerateMasterKeyBase64() (string, error) {
	key, err := GenerateMasterKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Returns: nonce(12) + ciphertext + tag(16), all base64-encoded.
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data encrypted with Encrypt.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	if len(ciphertext) < NonceSize+TagSize+1 {
		return nil, ErrTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}
