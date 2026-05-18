package crypto

import (
	"fmt"

	"golang.org/x/crypto/twofish"
)

func encryptTwofish(derivedKey, plaintext []byte) (*EncryptResult, error) {
	block, err := twofish.NewCipher(derivedKey[:32])
	if err != nil {
		return nil, fmt.Errorf("Twofish: new cipher: %w", err)
	}
	nonce24, ct, err := cbcEncryptWithIV(block, plaintext)
	if err != nil {
		return nil, fmt.Errorf("Twofish: %w", err)
	}
	return &EncryptResult{Nonce: nonce24, Payload: ct}, nil
}

func decryptTwofish(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	block, err := twofish.NewCipher(derivedKey[:32])
	if err != nil {
		return nil, fmt.Errorf("Twofish: new cipher: %w", err)
	}
	plain, err := cbcDecryptWithIV(block, nonce24, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Twofish: %w", err)
	}
	return plain, nil
}
