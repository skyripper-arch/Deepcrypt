package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptChaCha(derivedKey, plaintext []byte) (*EncryptResult, error) {
	aead, err := chacha20poly1305.NewX(derivedKey) // XChaCha20 — 24-byte nonce
	if err != nil {
		return nil, fmt.Errorf("ChaCha20: new AEAD: %w", err)
	}

	var nonce24 [24]byte
	if _, err := rand.Read(nonce24[:]); err != nil {
		return nil, fmt.Errorf("ChaCha20: nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce24[:], plaintext, nil)

	// KeyData is set by the caller (encrypt command) to [salt ‖ sessionSeed].
	return &EncryptResult{
		Nonce:   nonce24,
		Payload: ciphertext,
	}, nil
}

func decryptChaCha(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20: new AEAD: %w", err)
	}
	plain, err := aead.Open(nil, nonce24[:24], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20: decrypt failed (wrong key or corrupted data): %w", err)
	}
	return plain, nil
}
