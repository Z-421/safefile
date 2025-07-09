package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"errors"
)

func Encrypt(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {
	if len(key) != 32 {
		return nil, nil, errors.New("invalid key length")
	}
	nonce = make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcmAead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = gcmAead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func Decrypt(ciphertext []byte, key []byte, nonce []byte) (plaintext []byte, err error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcmAead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	plaintext, err = gcmAead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
