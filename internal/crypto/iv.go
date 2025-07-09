package crypto

import (
	"crypto/rand"
	"errors"
)

func GenerateIV() ([]byte, error) {
	IV := make([]byte, 16)
	_, err := rand.Read(IV)
	if err != nil {
		return nil, errors.New("invalid IV")
	}
	return IV, nil
}
