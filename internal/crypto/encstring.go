package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EncString is a symmetric encrypted value: "2.<iv>|<data>|<mac>".
type EncString struct {
	Type int
	IV   []byte
	Data []byte
	MAC  []byte
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// splitEncString splits "<type>.<part>|<part>...".
func splitEncString(s string) (int, []string, error) {
	head, rest, ok := strings.Cut(s, ".")
	if !ok {
		return 0, nil, ErrInvalidFormat
	}
	t, err := strconv.Atoi(head)
	if err != nil {
		return 0, nil, ErrInvalidFormat
	}
	return t, strings.Split(rest, "|"), nil
}

// ParseEncString parses a symmetric EncString. Only type 2
// (AES-256-CBC with HMAC-SHA256) is supported.
func ParseEncString(s string) (*EncString, error) {
	t, parts, err := splitEncString(s)
	if err != nil {
		return nil, err
	}
	switch {
	case t == 7:
		return nil, fmt.Errorf("%w: COSE (type 7) is not supported", ErrUnsupported)
	case t != 2 || len(parts) != 3:
		return nil, ErrInvalidFormat
	}
	e := &EncString{Type: t}
	if e.IV, err = unb64(parts[0]); err != nil {
		return nil, ErrInvalidFormat
	}
	if e.Data, err = unb64(parts[1]); err != nil {
		return nil, ErrInvalidFormat
	}
	if e.MAC, err = unb64(parts[2]); err != nil {
		return nil, ErrInvalidFormat
	}
	if len(e.IV) != 16 || len(e.MAC) != 32 {
		return nil, ErrInvalidFormat
	}
	return e, nil
}

func (e *EncString) String() string {
	return strconv.Itoa(e.Type) + "." + b64(e.IV) + "|" + b64(e.Data) + "|" + b64(e.MAC)
}

// Decrypt decrypts with key.
func (e *EncString) Decrypt(key *SymmetricKey) ([]byte, error) {
	return aesDecrypt(key, e.IV, e.Data, e.MAC)
}

// Encrypt encrypts plaintext with key as a type 2 EncString.
func Encrypt(key *SymmetricKey, plain []byte) (*EncString, error) {
	iv, ct, mac, err := aesEncrypt(key, plain)
	if err != nil {
		return nil, err
	}
	return &EncString{Type: 2, IV: iv, Data: ct, MAC: mac}, nil
}

// EncryptString encrypts a UTF-8 string and returns the serialized EncString.
func EncryptString(key *SymmetricKey, s string) (string, error) {
	e, err := Encrypt(key, []byte(s))
	if err != nil {
		return "", err
	}
	return e.String(), nil
}

// DecryptBytes parses and decrypts a serialized EncString.
func DecryptBytes(key *SymmetricKey, s string) ([]byte, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	return e.Decrypt(key)
}

// DecryptString parses and decrypts a serialized EncString to a string.
func DecryptString(key *SymmetricKey, s string) (string, error) {
	b, err := DecryptBytes(key, s)
	return string(b), err
}

// DecryptKey decrypts an EncString holding a symmetric key.
func DecryptKey(key *SymmetricKey, s string) (*SymmetricKey, error) {
	b, err := DecryptBytes(key, s)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

// DecryptUserKey decrypts the protected user key with the stretched master key.
func DecryptUserKey(masterKey []byte, protected string) (*SymmetricKey, error) {
	return DecryptKey(StretchKey(masterKey), protected)
}
