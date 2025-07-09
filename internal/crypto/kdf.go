package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/scrypt"
)

const (
	N      = 1 << 15 //cpu memory cost
	r      = 8       // block size
	p      = 1       // parallelization
	keyLen = 32
)

func DeriveKey(password []byte, salt []byte, N int, r int, p int, keyLen int) (key []byte, err error) {
	if (len(password) == 0) || (len(salt) == 0) || (N != 1<<15) || (r != 8) || (p != 1) || (keyLen != 32) {
		return nil, errors.New("invalid input parameters")
	}
	key, err = scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid size")
	}
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, errors.New("invalid salt")
	}
	return salt, nil
}
