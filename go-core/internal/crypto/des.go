package crypto

import (
	godes "crypto/des"
	"fmt"
)

// DES uses an 8-byte key (56 effective bits — intentionally weak).
func encryptDES(derivedKey, plaintext []byte) (*EncryptResult, error) {
	block, err := godes.NewCipher(derivedKey[:8])
	if err != nil {
		return nil, fmt.Errorf("DES: new cipher: %w", err)
	}
	nonce24, ct, err := cbcEncryptWithIV(block, plaintext)
	if err != nil {
		return nil, fmt.Errorf("DES: %w", err)
	}
	return &EncryptResult{Nonce: nonce24, Payload: ct}, nil
}

func decryptDES(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	block, err := godes.NewCipher(derivedKey[:8])
	if err != nil {
		return nil, fmt.Errorf("DES: new cipher: %w", err)
	}
	plain, err := cbcDecryptWithIV(block, nonce24, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("DES: %w", err)
	}
	return plain, nil
}

// 3DES uses a 24-byte key (three independent 8-byte DES keys).
func encrypt3DES(derivedKey, plaintext []byte) (*EncryptResult, error) {
	block, err := godes.NewTripleDESCipher(derivedKey[:24])
	if err != nil {
		return nil, fmt.Errorf("3DES: new cipher: %w", err)
	}
	nonce24, ct, err := cbcEncryptWithIV(block, plaintext)
	if err != nil {
		return nil, fmt.Errorf("3DES: %w", err)
	}
	return &EncryptResult{Nonce: nonce24, Payload: ct}, nil
}

func decrypt3DES(derivedKey, nonce24, ciphertext []byte) ([]byte, error) {
	block, err := godes.NewTripleDESCipher(derivedKey[:24])
	if err != nil {
		return nil, fmt.Errorf("3DES: new cipher: %w", err)
	}
	plain, err := cbcDecryptWithIV(block, nonce24, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("3DES: %w", err)
	}
	return plain, nil
}
