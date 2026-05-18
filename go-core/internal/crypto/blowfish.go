package crypto

import (
	"fmt"

	"golang.org/x/crypto/blowfish"
)

func encryptBlowfish(derivedKey, plaintext []byte) (*EncryptResult, error) {
	block, err := blowfish.NewCipher(derivedKey[:32])
	if err != nil {
		return nil, fmt.Errorf("Blowfish: new cipher: %w", err)
	}
	nonce24, ct, err := cbcEncryptWithIV(block, plaintext)
	if err != nil {
		return nil, fmt.Errorf("Blowfish: %w", err)
	}
	return &EncryptResult{Nonce: nonce24, Payload: ct}, nil
}

func decryptBlowfish(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	block, err := blowfish.NewCipher(derivedKey[:32])
	if err != nil {
		return nil, fmt.Errorf("Blowfish: new cipher: %w", err)
	}
	plain, err := cbcDecryptWithIV(block, nonce24, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Blowfish: %w", err)
	}
	return plain, nil
}
