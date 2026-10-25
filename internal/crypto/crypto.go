// Package crypto implements the Bitwarden client-side cryptography:
// KDFs, symmetric keys, EncStrings, encrypted buffers and RSA key wrapping.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/yangxiang/bw/internal/wordlist"
)

var (
	ErrMACMismatch   = errors.New("MAC comparison failed. Key or payload is invalid.")
	ErrInvalidKey    = errors.New("invalid key")
	ErrBadPadding    = errors.New("invalid padding")
	ErrUnsupported   = errors.New("unsupported encryption type")
	ErrInvalidFormat = errors.New("invalid EncString format")
)

// KDF types as used by the server.
const (
	KDFPBKDF2   = 0
	KDFArgon2id = 1
)

// KDFParams are the account's key derivation settings.
type KDFParams struct {
	Type        int
	Iterations  int
	Memory      int // MiB
	Parallelism int
}

// SymmetricKey is an AES-256-CBC key with an optional HMAC-SHA256 key.
type SymmetricKey struct {
	Enc []byte
	Mac []byte
}

// NewSymmetricKey builds a key from raw bytes: 64 bytes = enc||mac, 32 bytes = enc only.
func NewSymmetricKey(b []byte) (*SymmetricKey, error) {
	switch len(b) {
	case 64:
		return &SymmetricKey{Enc: bytes.Clone(b[:32]), Mac: bytes.Clone(b[32:])}, nil
	case 32:
		return &SymmetricKey{Enc: bytes.Clone(b)}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key length %d (v2 encryption keys are not supported)", ErrInvalidKey, len(b))
	}
}

// GenerateSymmetricKey returns a new random 64-byte AES+HMAC key.
func GenerateSymmetricKey() *SymmetricKey {
	k, _ := NewSymmetricKey(RandomBytes(64))
	return k
}

// Bytes returns enc||mac.
func (k *SymmetricKey) Bytes() []byte { return append(bytes.Clone(k.Enc), k.Mac...) }

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// MasterKey derives the master key from password and email.
func MasterKey(password, email string, p KDFParams) ([]byte, error) {
	salt := []byte(strings.ToLower(strings.TrimSpace(email)))
	return DeriveKDF([]byte(password), salt, p)
}

// DeriveKDF runs PBKDF2-SHA256 or Argon2id producing a 32-byte key.
func DeriveKDF(secret, salt []byte, p KDFParams) ([]byte, error) {
	switch p.Type {
	case KDFPBKDF2:
		if p.Iterations < 5000 {
			return nil, errors.New("Insufficient KDF parameters")
		}
		return pbkdf2.Key(sha256.New, string(secret), salt, p.Iterations, 32)
	case KDFArgon2id:
		if p.Memory < 16 || p.Iterations < 2 || p.Parallelism < 1 {
			return nil, errors.New("Insufficient KDF parameters")
		}
		s := sha256.Sum256(salt)
		return argon2.IDKey(secret, s[:], uint32(p.Iterations), uint32(p.Memory*1024), uint8(p.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", p.Type)
	}
}

// MasterPasswordHash is the server authorization hash: PBKDF2(masterKey, password, 1).
func MasterPasswordHash(masterKey []byte, password string) string {
	h, _ := pbkdf2.Key(sha256.New, string(masterKey), []byte(password), 1, 32)
	return base64.StdEncoding.EncodeToString(h)
}

// StretchKey expands a 32-byte key into an enc+mac key with HKDF-Expand.
func StretchKey(key []byte) *SymmetricKey {
	enc, _ := hkdf.Expand(sha256.New, key, "enc", 32)
	mac, _ := hkdf.Expand(sha256.New, key, "mac", 32)
	return &SymmetricKey{Enc: enc, Mac: mac}
}

// ShareableKey derives a key from a 16-byte secret (used for Sends):
// HKDF with salt "bitwarden-<name>" and the given info.
func ShareableKey(secret []byte, name, info string) *SymmetricKey {
	b, _ := hkdf.Key(sha256.New, secret, []byte("bitwarden-"+name), info, 64)
	k, _ := NewSymmetricKey(b)
	return k
}

// Fingerprint returns the 5-word account fingerprint phrase.
func Fingerprint(material string, publicKey []byte) (string, error) {
	h, err := hkdf.Expand(sha256.New, publicKey, material, 32)
	if err != nil {
		return "", err
	}
	n := new(big.Int).SetBytes(h)
	size := big.NewInt(int64(len(wordlist.EFFLong)))
	words := make([]string, 0, 5)
	rem := new(big.Int)
	for range 5 {
		n.DivMod(n, size, rem)
		words = append(words, wordlist.EFFLong[rem.Int64()])
	}
	return strings.Join(words, "-"), nil
}

// --- AES-CBC helpers ---

func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(bytes.Clone(b), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, ErrBadPadding
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, ErrBadPadding
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, ErrBadPadding
		}
	}
	return b[:len(b)-n], nil
}

func computeMAC(key, iv, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(iv)
	m.Write(data)
	return m.Sum(nil)
}

func aesEncrypt(key *SymmetricKey, plain []byte) (iv, ct, mac []byte, err error) {
	block, err := aes.NewCipher(key.Enc)
	if err != nil {
		return nil, nil, nil, err
	}
	iv = RandomBytes(aes.BlockSize)
	padded := pkcs7Pad(plain)
	ct = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	if key.Mac != nil {
		mac = computeMAC(key.Mac, iv, ct)
	}
	return iv, ct, mac, nil
}

func aesDecrypt(key *SymmetricKey, encType int, iv, ct, mac []byte) ([]byte, error) {
	switch encType {
	case 0:
		if key.Mac != nil {
			// The official clients refuse to decrypt unauthenticated data with an authenticated key.
			return nil, ErrMACMismatch
		}
	case 2:
		if key.Mac == nil || !hmac.Equal(mac, computeMAC(key.Mac, iv, ct)) {
			return nil, ErrMACMismatch
		}
	default:
		return nil, ErrUnsupported
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, ErrInvalidFormat
	}
	block, err := aes.NewCipher(key.Enc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return pkcs7Unpad(out)
}

// EncryptBuffer encrypts binary data (attachments, Send files) into the
// EncArrayBuffer layout: type(1) | iv(16) | mac(32) | ciphertext.
func EncryptBuffer(key *SymmetricKey, plain []byte) ([]byte, error) {
	if key.Mac == nil {
		return nil, ErrInvalidKey
	}
	iv, ct, mac, err := aesEncrypt(key, plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(iv)+len(mac)+len(ct))
	out = append(out, 2)
	out = append(out, iv...)
	out = append(out, mac...)
	return append(out, ct...), nil
}

// DecryptBuffer decrypts the EncArrayBuffer layout.
func DecryptBuffer(key *SymmetricKey, buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, ErrInvalidFormat
	}
	switch buf[0] {
	case 0:
		if len(buf) < 18 {
			return nil, ErrInvalidFormat
		}
		return aesDecrypt(key, 0, buf[1:17], buf[17:], nil)
	case 2:
		if len(buf) < 50 {
			return nil, ErrInvalidFormat
		}
		return aesDecrypt(key, 2, buf[1:17], buf[49:], buf[17:49])
	default:
		return nil, ErrUnsupported
	}
}
