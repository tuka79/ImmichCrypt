package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ShamirShare represents one piece of a split secret.
type ShamirShare struct {
	X int    `json:"x"` // point x coordinate (1, 2, 3...)
	Y string `json:"y"` // point y coordinate (base64, 32 bytes)
}

// Split divides a 32-byte secret into n shares, requiring k to recover.
// Uses GF(256) arithmetic. Each share is 32 bytes + 1 byte for x.
func Split(secret []byte, n, k int) ([]ShamirShare, error) {
	if len(secret) != KeySize {
		return nil, fmt.Errorf("secret must be 32 bytes, got %d", len(secret))
	}
	if k > n {
		return nil, errors.New("threshold k cannot exceed total shares n")
	}
	if n > 255 {
		return nil, errors.New("max 255 shares")
	}

	coeffs := make([][]byte, k)
	coeffs[0] = make([]byte, KeySize)
	copy(coeffs[0], secret)

	for i := 1; i < k; i++ {
		coeffs[i] = make([]byte, KeySize)
		if _, err := rand.Read(coeffs[i]); err != nil {
			return nil, err
		}
	}

	shares := make([]ShamirShare, n)
	for i := 0; i < n; i++ {
		x := byte(i + 1)
		y := evaluatePolynomial(coeffs, x)
		shares[i] = ShamirShare{
			X: i + 1,
			Y: base64.StdEncoding.EncodeToString(y)[:44],
		}
	}

	return shares, nil
}

// Recover reconstructs the secret from k shares using Lagrange interpolation.
func Recover(shares []ShamirShare, k int) ([]byte, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("need %d shares, have %d", k, len(shares))
	}

	secret := make([]byte, KeySize)

	for i := 0; i < k; i++ {
		yBytes, err := base64.StdEncoding.DecodeString(shares[i].Y + "=")
		if err != nil {
			return nil, fmt.Errorf("share %d decode: %w", i, err)
		}

		numerator := byte(1)
		denominator := byte(1)

		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			numerator = gfMul(numerator, byte(shares[j].X))
			diff := byte(shares[j].X) ^ byte(shares[i].X)
			denominator = gfMul(denominator, diff)
		}

		lagrange := gfDiv(numerator, denominator)

		for b := 0; b < KeySize; b++ {
			secret[b] ^= gfMul(yBytes[b], lagrange)
		}
	}

	return secret, nil
}

// evaluatePolynomial computes P(x) for a polynomial with given coefficients.
func evaluatePolynomial(coeffs [][]byte, x byte) []byte {
	result := make([]byte, KeySize)

	for i := len(coeffs) - 1; i >= 0; i-- {
		for b := 0; b < KeySize; b++ {
			result[b] = gfMul(result[b], x) ^ coeffs[i][b]
		}
	}

	return result
}

// GenerateRecoveryEmails creates k-of-n Shamir shares with verification hashes.
func GenerateRecoveryEmails(masterKey []byte, n, k int) (shares []ShamirShare, verifyHash string, err error) {
	shares, err = Split(masterKey, n, k)
	if err != nil {
		return nil, "", err
	}

	h := sha256.Sum256(masterKey)
	verifyHash = base64.StdEncoding.EncodeToString(h[:])

	return shares, verifyHash, nil
}

// VerifyRecovery checks if recovered key matches the stored hash.
func VerifyRecovery(recoveredKey []byte, storedHash string) bool {
	h := sha256.Sum256(recoveredKey)
	return base64.StdEncoding.EncodeToString(h[:]) == storedHash
}

// GF(256) arithmetic for Shamir's Secret Sharing.
// Field: GF(2^8) with primitive polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).

const gfPrimitive = 0x11B

func gfMul(a, b byte) byte {
	var product uint16
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			product ^= uint16(a)
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return byte(product)
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfInverse(b))
}

func gfInverse(a byte) byte {
	if a == 0 {
		return 0
	}
	result := a
	for i := 0; i < 254; i++ {
		result = gfMul(result, a)
	}
	return result
}
