package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

func EncryptAES(key []byte, plaintext []byte) ([]byte, error) {
	// create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("nonce  err: %v", err.Error())
	}

	cipherText := gcm.Seal(nonce, nonce, plaintext, nil)

	// return hex string
	return cipherText, nil
}

func DecryptAES(key []byte, ciphertext []byte) ([]byte, error) {
	//ciphertext, _ := hex.DecodeString(ct)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}

	//fmt.Println("DECRYPTED:", s)
	return plainText, nil
}
