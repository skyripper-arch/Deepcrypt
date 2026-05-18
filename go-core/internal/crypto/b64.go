package crypto

import (
	"encoding/base64"
	"fmt"
)

// Base64 is encoding only — no cryptographic security whatsoever.
// The derived key is intentionally ignored; anyone can reverse this.
func encryptB64(_ /*derivedKey*/, plaintext []byte) (*EncryptResult, error) {
	encoded := base64.StdEncoding.EncodeToString(plaintext)
	return &EncryptResult{Payload: []byte(encoded)}, nil
}

func decryptB64(_ /*derivedKey*/, _ /*nonce*/, ciphertext []byte) ([]byte, error) {
	plain, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("Base64: decode failed: %w", err)
	}
	return plain, nil
}
