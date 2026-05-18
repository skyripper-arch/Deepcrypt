package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Hybrid ECIES over Curve25519:
// 1. Generate recipient key pair; store private key in .key file.
// 2. Generate ephemeral key pair per encryption.
// 3. X25519 ECDH → shared secret → HKDF-SHA256 → 32-byte DEK.
// 4. XChaCha20-Poly1305 encrypts the file with the DEK.
// Payload layout: [32-byte ephemeral pubkey][XChaCha20 ciphertext]
// Nonce: 24-byte XChaCha20 nonce stored in the header.

func encryptECC(plaintext []byte) (*EncryptResult, error) {
	// Recipient key pair (written to .key file)
	recipientPriv := make([]byte, 32)
	if _, err := rand.Read(recipientPriv); err != nil {
		return nil, fmt.Errorf("ECC: recipient private key: %w", err)
	}
	recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("ECC: recipient public key: %w", err)
	}

	// Ephemeral key pair (embedded in payload)
	ephemeralPriv := make([]byte, 32)
	if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, fmt.Errorf("ECC: ephemeral private key: %w", err)
	}
	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("ECC: ephemeral public key: %w", err)
	}

	// ECDH shared secret
	shared, err := curve25519.X25519(ephemeralPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECC: ECDH: %w", err)
	}

	dek, err := hkdfDerive(shared)
	if err != nil {
		return nil, err
	}

	// XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("ECC: ChaCha20: %w", err)
	}

	var nonce24 [24]byte
	if _, err := rand.Read(nonce24[:]); err != nil {
		return nil, fmt.Errorf("ECC: nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce24[:], plaintext, nil)

	// Payload = ephemeral pubkey || ciphertext
	payload := append(ephemeralPub, ciphertext...)

	return &EncryptResult{
		Nonce:   nonce24,
		Payload: payload,
		KeyData: recipientPriv,
	}, nil
}

func decryptECC(recipientPriv, nonce24, payload []byte) ([]byte, error) {
	if len(payload) < 32 {
		return nil, fmt.Errorf("ECC: payload too short")
	}
	ephemeralPub := payload[:32]
	ciphertext := payload[32:]

	shared, err := curve25519.X25519(recipientPriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECC: ECDH: %w", err)
	}

	dek, err := hkdfDerive(shared)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("ECC: ChaCha20: %w", err)
	}

	plain, err := aead.Open(nil, nonce24[:24], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ECC: decrypt failed (wrong key or corrupted data): %w", err)
	}
	return plain, nil
}

func hkdfDerive(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte("deepcrypt-ecc-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("ECC: HKDF: %w", err)
	}
	return key, nil
}
