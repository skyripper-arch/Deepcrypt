package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

// Hybrid: RSA-4096-OAEP encrypts a random 32-byte DEK; AES-256-GCM encrypts the file.
// Payload layout: [4-byte encDEK_len][encDEK][AES-GCM ciphertext]
// KeyData: PKCS8-encoded RSA private key.

func encryptRSA(plaintext []byte) (*EncryptResult, error) {
	fmt.Println("[deepcrypt] Generating RSA-4096 key pair (this takes a moment)...")
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("RSA: key generation: %w", err)
	}

	// Random 32-byte data-encryption key (DEK)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("RSA: DEK generation: %w", err)
	}

	// Encrypt DEK with RSA-OAEP SHA-256
	encDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privKey.PublicKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA: OAEP encrypt DEK: %w", err)
	}

	// Random 12-byte AES-GCM nonce
	nonce12 := make([]byte, 12)
	if _, err := rand.Read(nonce12); err != nil {
		return nil, fmt.Errorf("RSA: AES nonce: %w", err)
	}

	ciphertext, err := aesGCMEncrypt(dek, nonce12, plaintext)
	if err != nil {
		return nil, fmt.Errorf("RSA: AES-GCM encrypt: %w", err)
	}

	// Serialize private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("RSA: marshal private key: %w", err)
	}

	// Build payload
	payload := make([]byte, 4+len(encDEK)+len(ciphertext))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(encDEK)))
	copy(payload[4:], encDEK)
	copy(payload[4+len(encDEK):], ciphertext)

	var nonce24 [24]byte
	copy(nonce24[:], nonce12)

	return &EncryptResult{
		Nonce:   nonce24,
		Payload: payload,
		KeyData: privBytes,
	}, nil
}

func decryptRSA(privKeyBytes, nonce24, payload []byte) ([]byte, error) {
	keyIface, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("RSA: parse private key: %w", err)
	}
	privKey, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA: key is not an RSA private key")
	}

	if len(payload) < 4 {
		return nil, fmt.Errorf("RSA: payload too short")
	}
	dekLen := int(binary.BigEndian.Uint32(payload[:4]))
	if len(payload) < 4+dekLen {
		return nil, fmt.Errorf("RSA: payload truncated")
	}
	encDEK := payload[4 : 4+dekLen]
	ciphertext := payload[4+dekLen:]

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA: OAEP decrypt DEK: %w", err)
	}

	nonce12 := nonce24[:12]
	return aesGCMDecrypt(dek, nonce12, ciphertext)
}
