package safefile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"github.com/Z-421/safefile/internal/crypto"
	"github.com/Z-421/safefile/internal/utils"
)

type EncryptedFileData struct {
	Salt       string
	Nonce      string
	Ciphertext string
	HMAC       string
}

func EncryptAndSaveFile(inputPath string, outputPath string, password []byte) (err error) {
	if !utils.FileExists(inputPath) {
		return errors.New("input file does not exist")
	}
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveKey(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return err
	}
	hmac, err := crypto.GenerateHMAC(ciphertext, nonce)
	if err != nil {
		return err
	}

	group := EncryptedFileData{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		HMAC:       base64.StdEncoding.EncodeToString(hmac),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	marshal, err := json.Marshal(group)
	if err != nil {
		return err
	}
	err = os.WriteFile(outputPath, marshal, 0600)
	if err != nil {
		return err
	}
	err = os.Remove(inputPath)
	if err != nil {
		return err
	}
	return nil
}

func DecryptAndSaveFile(inputPath string, outputPath string, password []byte) (err error) {
	if !utils.FileExists(inputPath) {
		return errors.New("encrypted file does not exist")
	}
	group, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var decryptedFileData EncryptedFileData
	err = json.Unmarshal(group, &decryptedFileData)
	if err != nil {
		return nil
	}
	salt, err := base64.StdEncoding.DecodeString(decryptedFileData.Salt)
	if err != nil {
		return nil
	}
	nonce, err := base64.StdEncoding.DecodeString(decryptedFileData.Nonce)
	if err != nil {
		return nil
	}
	hmac, err := base64.StdEncoding.DecodeString(decryptedFileData.HMAC)
	if err != nil {
		return nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(decryptedFileData.Ciphertext)
	if err != nil {
		return nil
	}
	key, err := crypto.DeriveKey(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil
	}
	generatedHmac, err := crypto.GenerateHMAC(ciphertext, nonce)
	if err != nil {
		return nil
	}
	if !bytes.Equal(generatedHmac, hmac) {
		return errors.New("HMAC mismatch")
	}
	plaintext, err := crypto.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return nil
	}
	err = os.WriteFile(outputPath, plaintext, 0600)
	if err != nil {
		return nil
	}
	return nil
}
