package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"hash"
)

// ParsePrivateKey parses a PKCS#8 DER RSA private key.
func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// PublicKeyDER returns the SPKI DER encoding of the private key's public key.
func PublicKeyDER(k *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

// DecryptRSA decrypts an asymmetric EncString: type 3 (RSA-OAEP-SHA256) or
// type 4 (RSA-OAEP-SHA1).
func DecryptRSA(priv *rsa.PrivateKey, s string) ([]byte, error) {
	t, parts, err := splitEncString(s)
	if err != nil {
		return nil, err
	}
	if len(parts) != 1 {
		return nil, ErrInvalidFormat
	}
	var h hash.Hash
	switch t {
	case 3:
		h = sha256.New()
	case 4:
		h = sha1.New()
	default:
		return nil, ErrInvalidFormat
	}
	data, err := unb64(parts[0])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	return rsa.DecryptOAEP(h, nil, priv, data, nil)
}

// EncryptRSA wraps data for an SPKI DER public key as type 4 (RSA-OAEP-SHA1),
// the format the official clients use for org/emergency keys.
func EncryptRSA(publicKeyDER, data []byte) (string, error) {
	k, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return "", err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("public key is not RSA")
	}
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return "", err
	}
	return "4." + b64(ct), nil
}

// GenerateKeyPair creates a 2048-bit RSA key pair returning (SPKI DER, PKCS#8 DER).
func GenerateKeyPair() (pub, priv []byte, err error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	if pub, err = x509.MarshalPKIXPublicKey(&k.PublicKey); err != nil {
		return nil, nil, err
	}
	priv, err = x509.MarshalPKCS8PrivateKey(k)
	return pub, priv, err
}
