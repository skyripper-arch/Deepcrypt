package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func encryptAES(derivedKey, plaintext []byte) (*EncryptResult, error) {
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("AES: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES: new GCM: %w", err)
	}

	nonce12 := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce12); err != nil {
		return nil, fmt.Errorf("AES: nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce12, plaintext, nil)

	var nonce24 [24]byte
	copy(nonce24[:], nonce12)

	// KeyData is set by the caller (encrypt command) to [salt ‖ sessionSeed].
	return &EncryptResult{
		Nonce:   nonce24,
		Payload: ciphertext,
	}, nil
}

func decryptAES(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("AES: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES: new GCM: %w", err)
	}
	nonce12 := nonce24[:gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce12, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES: decrypt failed (wrong key or corrupted data): %w", err)
	}
	return plain, nil
}

// aesGCMEncrypt is a low-level helper used by RSA and PQC hybrid encryption.
func aesGCMEncrypt(key, nonce12, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce12, plaintext, nil), nil
}

// aesGCMDecrypt is a low-level helper used by RSA and PQC hybrid decryption.
func aesGCMDecrypt(key, nonce12, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce12, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM: authentication failed: %w", err)
	}
	return plain, nil
}
