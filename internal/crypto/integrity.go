package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func GenerateHMAC(message []byte, key []byte) (HMAC []byte, err error) {
	if (len(key) == 0) || (len(message) == 0) {
		return nil, errors.New("empty key or message")
	}

	h := hmac.New(sha256.New, key)
	_, err = h.Write(message)
	if err != nil {
		return nil, err
	}
	HMAC = h.Sum(nil)
	return HMAC, nil
}

func VerifyHMAC(message []byte, key []byte, expectedHMAC []byte) (bool, error) {
	if (len(key) == 0) || (len(message) == 0) || (len(expectedHMAC) == 0) {
		return false, errors.New("invalid input")
	}
	generatedHMAC, err := GenerateHMAC(message, key)
	if err != nil {
		return false, err
	}
	isValid := hmac.Equal(generatedHMAC, expectedHMAC)
	return isValid, nil
}
