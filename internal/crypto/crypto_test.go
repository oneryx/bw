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

func TestFingerprint(t *testing.T) {
	key := []byte{48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 187, 38, 44, 241, 110, 205, 89, 253, 25, 191, 126, 84, 121, 202, 61, 223, 189, 244, 118, 212, 74, 139, 130, 97, 115, 164, 167, 106, 191, 188, 233, 218, 196, 250, 187, 146, 125, 160, 150, 49, 198, 224, 176, 10, 0, 143, 99, 230, 232, 160, 51, 104, 154, 211, 33, 80, 170, 4, 68, 80, 219, 115, 167, 114, 156, 227, 125, 193, 128, 123, 39, 254, 191, 124, 63, 129, 44, 63, 18, 56, 161, 48, 158, 0, 27, 146, 2, 99, 136, 75, 21, 135, 6, 118, 12, 26, 251, 184, 172, 249, 53, 78, 210, 46, 143, 17, 104, 202, 65, 173, 229, 219, 233, 144, 163, 101, 216, 238, 152, 54, 158, 1, 195, 50, 203, 21, 226, 12, 82, 170, 175, 170, 160, 21, 247, 248, 80, 97, 123, 0, 152, 116, 229, 126, 221, 199, 155, 194, 192, 51, 207, 177, 240, 160, 84, 241, 41, 88, 176, 53, 111, 28, 173, 177, 232, 158, 22, 79, 133, 152, 31, 32, 12, 196, 147, 58, 57, 50, 252, 208, 131, 150, 179, 132, 178, 150, 234, 251, 143, 125, 163, 144, 20, 46, 71, 168, 252, 164, 86, 120, 124, 56, 252, 206, 210, 236, 212, 139, 127, 189, 236, 40, 46, 2, 238, 13, 216, 40, 48, 85, 133, 229, 181, 155, 176, 217, 241, 154, 153, 213, 112, 222, 72, 219, 197, 3, 219, 56, 77, 109, 47, 72, 251, 131, 36, 240, 96, 169, 31, 82, 93, 166, 242, 3, 33, 213, 2, 3, 1, 0, 1}
	got, err := Fingerprint("a09726a0-9590-49d1-a5f5-afe300b6a515", key)
	if err != nil {
		t.Fatal(err)
	}
	if got != "turban-deftly-anime-chatroom-unselfish" {
		t.Fatalf("got %s", got)
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
