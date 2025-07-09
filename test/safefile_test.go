package test

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"github.com/Z-421/safefile/internal/crypto"
	"github.com/Z-421/safefile/safefile"
)

func TestGenerateSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("Expected salt of length 16, got: %d", len(salt))
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("mypassword")
	salt := []byte("12345678abcdefgh")
	N := 1 << 15
	r := 8
	p := 1
	keyLen := 32

	key, err := crypto.DeriveKey(password, salt, N, r, p, keyLen)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	if len(key) != keyLen {
		t.Errorf("Expected key length %d, got %d", keyLen, len(key))
	}
}

func TestGenerateIV(t *testing.T) {
	iv, err := crypto.GenerateIV()
	if err != nil {
		t.Fatalf("GenerateIV returned error: %v", err)
	}
	if len(iv) != 16 {
		t.Fatalf("Expected IV length 16, got %d", len(iv))
	}
}

func TestEncrypt(t *testing.T) {

	plaintext := []byte("Hello, this is a secret message!")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	ciphertext, nonce, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Errorf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("ciphertext is empty")
	}
	if len(nonce) != 12 {
		t.Errorf("nonce has invalid length: got %d, want 12", len(nonce))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("This is a secret message")

	ciphertext, nonce, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted text does not match original plaintext")
	}
}

func TestVerifyHMAC(t *testing.T) {
	message := []byte("This is a secret message")
	key := []byte("my_hmac_key")

	hmacValue, err := crypto.GenerateHMAC(message, key)
	if err != nil {
		t.Fatalf("failed to generate HMAC: %v", err)
	}

	valid, err := crypto.VerifyHMAC(message, key, hmacValue)
	if err != nil {
		t.Errorf("unexpected error verifying valid HMAC: %v", err)
	}
	if !valid {
		t.Errorf("expected valid HMAC to verify correctly")
	}

	fakeHMAC := []byte("invalidhmacvalue")
	valid, err = crypto.VerifyHMAC(message, key, fakeHMAC)
	if err != nil {
		t.Errorf("unexpected error verifying fake HMAC: %v", err)
	}
	if valid {
		t.Errorf("expected invalid HMAC to fail verification")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {

	originalContent := []byte("Hello, Safefile!")

	inputFile, err := os.CreateTemp("", "input-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp input file: %v", err)
	}
	defer os.Remove(inputFile.Name())
	_, err = inputFile.Write(originalContent)
	if err != nil {
		t.Fatalf("failed to write to temp input file: %v", err)
	}
	inputFile.Close()

	encryptedFile := inputFile.Name() + ".enc"
	defer os.Remove(encryptedFile)

	password := []byte("strongpassword123")
	err = safefile.EncryptAndSaveFile(inputFile.Name(), encryptedFile, password)
	if err != nil {
		t.Fatalf("EncryptAndSaveFile failed: %v", err)
	}

	decryptedFile := inputFile.Name() + ".dec"
	defer os.Remove(decryptedFile)

	err = safefile.DecryptAndSaveFile(encryptedFile, decryptedFile, password)
	if err != nil {
		t.Fatalf("DecryptAndSaveFile failed: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Errorf("decrypted content does not match original")
	}
}
