package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EncString is a symmetric encrypted value: "<type>.<iv>|<data>|<mac>".
type EncString struct {
	Type int
	IV   []byte
	Data []byte
	MAC  []byte
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// splitEncString mirrors the SDK: "<type>.<parts>" or the legacy headerless form.
func splitEncString(s string) (int, []string, error) {
	head, rest, ok := strings.Cut(s, ".")
	if ok && !strings.Contains(rest, ".") {
		t, err := strconv.Atoi(head)
		if err != nil {
			return 0, nil, ErrInvalidFormat
		}
		return t, strings.Split(rest, "|"), nil
	}
	parts := strings.Split(s, "|")
	if len(parts) == 3 {
		return 1, parts, nil
	}
	return 0, parts, nil
}

// ParseEncString parses a symmetric EncString.
func ParseEncString(s string) (*EncString, error) {
	t, parts, err := splitEncString(s)
	if err != nil {
		return nil, err
	}
	dec := func(i int) ([]byte, error) { return unb64(parts[i]) }
	e := &EncString{Type: t}
	switch {
	case t == 0 && len(parts) == 2:
		if e.IV, err = dec(0); err != nil {
			return nil, ErrInvalidFormat
		}
		if e.Data, err = dec(1); err != nil {
			return nil, ErrInvalidFormat
		}
	case t == 2 && len(parts) == 3:
		if e.IV, err = dec(0); err != nil {
			return nil, ErrInvalidFormat
		}
		if e.Data, err = dec(1); err != nil {
			return nil, ErrInvalidFormat
		}
		if e.MAC, err = dec(2); err != nil {
			return nil, ErrInvalidFormat
		}
	case t == 7:
		return nil, fmt.Errorf("%w: COSE (type 7) is not supported", ErrUnsupported)
	default:
		return nil, ErrInvalidFormat
	}
	if len(e.IV) != 16 || (e.Type == 2 && len(e.MAC) != 32) {
		return nil, ErrInvalidFormat
	}
	return e, nil
}

func (e *EncString) String() string {
	switch e.Type {
	case 0:
		return "0." + b64(e.IV) + "|" + b64(e.Data)
	default:
		return strconv.Itoa(e.Type) + "." + b64(e.IV) + "|" + b64(e.Data) + "|" + b64(e.MAC)
	}
}

// Decrypt decrypts with key.
func (e *EncString) Decrypt(key *SymmetricKey) ([]byte, error) {
	return aesDecrypt(key, e.Type, e.IV, e.Data, e.MAC)
}

// Encrypt encrypts plaintext with key (type 2, or type 0 for MAC-less keys).
func Encrypt(key *SymmetricKey, plain []byte) (*EncString, error) {
	iv, ct, mac, err := aesEncrypt(key, plain)
	if err != nil {
		return nil, err
	}
	t := 2
	if mac == nil {
		t = 0
	}
	return &EncString{Type: t, IV: iv, Data: ct, MAC: mac}, nil
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

// DecryptUserKey decrypts the protected user key with the master key,
// stretching it unless the legacy unauthenticated (type 0) format is used.
func DecryptUserKey(masterKey []byte, protected string) (*SymmetricKey, error) {
	e, err := ParseEncString(protected)
	if err != nil {
		return nil, err
	}
	var k *SymmetricKey
	if e.Type == 0 {
		k = &SymmetricKey{Enc: masterKey}
	} else {
		k = StretchKey(masterKey)
	}
	b, err := e.Decrypt(k)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}
