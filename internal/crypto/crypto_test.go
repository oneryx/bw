package crypto

import (
	"bytes"
	"testing"
)

// Test vectors from bitwarden/sdk-internal crates/bitwarden-crypto.

func TestMasterKeyPBKDF2(t *testing.T) {
	k, err := MasterKey("67t9b5g67$%Dh89n", "test_key", KDFParams{Type: KDFPBKDF2, Iterations: 10000})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75}
	if !bytes.Equal(k, want) {
		t.Fatalf("got %v", k)
	}
}

func TestMasterKeyArgon2(t *testing.T) {
	k, err := MasterKey("67t9b5g67$%Dh89n", "test_key", KDFParams{Type: KDFArgon2id, Iterations: 4, Memory: 32, Parallelism: 2})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147, 237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242}
	if !bytes.Equal(k, want) {
		t.Fatalf("got %v", k)
	}
}

func TestStretchKey(t *testing.T) {
	k := StretchKey([]byte{31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75})
	enc := []byte{111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142, 134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96}
	mac := []byte{221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127, 166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155}
	if !bytes.Equal(k.Enc, enc) || !bytes.Equal(k.Mac, mac) {
		t.Fatalf("got %v %v", k.Enc, k.Mac)
	}
}

func TestEncStringParse(t *testing.T) {
	s := "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8="
	e, err := ParseEncString(s)
	if err != nil {
		t.Fatal(err)
	}
	if e.String() != s {
		t.Fatalf("roundtrip: %s", e.String())
	}
	bad := []string{
		"2.AAECAw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"2.AAECAwQFBgcICQoLDA0ODw==|Y3Q=|AAECAw==",
		"0.AAECAwQFBgcICQoLDA0ODw==|Y3Q=",
		"AAECAwQFBgcICQoLDA0ODw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"2.!!!!|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"8.ABC",
		"7.ABC|DEF",
	}
	for _, b := range bad {
		if _, err := ParseEncString(b); err == nil {
			t.Errorf("expected error for %s", b)
		}
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	k := GenerateSymmetricKey()
	s, err := EncryptString(k, "hello wörld")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptString(k, s)
	if err != nil || got != "hello wörld" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := DecryptString(GenerateSymmetricKey(), s); err == nil {
		t.Fatal("expected MAC failure with wrong key")
	}
	buf, err := EncryptBuffer(k, []byte("file content"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptBuffer(k, buf)
	if err != nil || string(plain) != "file content" {
		t.Fatalf("buffer roundtrip: %q %v", plain, err)
	}
	buf[len(buf)-1] ^= 1
	if _, err := DecryptBuffer(k, buf); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestUserKeyFlow(t *testing.T) {
	kdf := KDFParams{Type: KDFPBKDF2, Iterations: 5000}
	mk, err := MasterKey("pw", "User@Example.com ", kdf)
	if err != nil {
		t.Fatal(err)
	}
	uk := GenerateSymmetricKey()
	e, err := Encrypt(StretchKey(mk), uk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	mk2, _ := MasterKey("pw", "user@example.com", kdf)
	got, err := DecryptUserKey(mk2, e.String())
	if err != nil || !bytes.Equal(got.Bytes(), uk.Bytes()) {
		t.Fatalf("user key mismatch: %v", err)
	}
}

func TestRSARoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	orgKey := GenerateSymmetricKey().Bytes()
	wrapped, err := EncryptRSA(pub, orgKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptRSA(pk, wrapped)
	if err != nil || !bytes.Equal(got, orgKey) {
		t.Fatalf("rsa roundtrip: %v", err)
	}
}
