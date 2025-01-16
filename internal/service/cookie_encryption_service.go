package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type CookieEncryptionService struct {
	key []byte
}

func NewCookieEncryptionService(key string) (*CookieEncryptionService, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (256 bits) long for AES-256")
	}
	return &CookieEncryptionService{key: []byte(key)}, nil
}

func (s *CookieEncryptionService) Encrypt(data map[string]string) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("error serializing data: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("error creating AES block cipher: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("error generating nonce: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating AES-GCM: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	finalData := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalData), nil
}

func (s *CookieEncryptionService) Decrypt(encrypted string) (map[string]string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("error decoding Base64: %w", err)
	}

	if len(ciphertext) < 12 {
		return nil, errors.New("encrypted data is too short")
	}

	nonce, ciphertext := ciphertext[:12], ciphertext[12:]

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES block cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating AES-GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %w", err)
	}

	var data map[string]string
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("error deserializing data: %w", err)
	}

	return data, nil
}
