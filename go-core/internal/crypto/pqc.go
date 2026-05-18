package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Hybrid ML-KEM-768 (Kyber768) + AES-256-GCM:
//
//  Encrypt:
//    1. Generate fresh Kyber768 key pair.
//    2. Encapsulate with public key → (KEM ciphertext ct, 32-byte shared secret ss).
//    3. AES-256-GCM encrypts the file using ss as the key.
//    Payload: [4-byte ct_len][ct][AES-GCM ciphertext]
//    KeyData: serialised private key (stored in .key file).
//    Nonce:   12-byte AES nonce, zero-padded to 24 bytes in header.
//
//  Decrypt:
//    1. Load private key from .key file.
//    2. Parse payload → ct, ciphertext.
//    3. Decapsulate(sk, ct) → ss.
//    4. AES-256-GCM decrypts with ss.

func encryptPQC(plaintext []byte) (*EncryptResult, error) {
	scheme := kyber768.Scheme()

	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("PQC: key generation: %w", err)
	}

	// Encapsulate: returns (KEM ciphertext, shared secret).
	kemCT, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, fmt.Errorf("PQC: encapsulate: %w", err)
	}
	if len(ss) < 32 {
		return nil, fmt.Errorf("PQC: shared secret too short (%d bytes, need 32)", len(ss))
	}
	dek := ss[:32] // Kyber768 ss is always 32 bytes; guard is defensive

	// AES-GCM nonce.
	nonce12 := make([]byte, 12)
	if _, err := rand.Read(nonce12); err != nil {
		return nil, fmt.Errorf("PQC: AES nonce: %w", err)
	}

	ct, err := aesGCMEncrypt(dek, nonce12, plaintext)
	if err != nil {
		return nil, fmt.Errorf("PQC: AES-GCM encrypt: %w", err)
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("PQC: marshal private key: %w", err)
	}

	// Payload: [4-byte kemCT_len][kemCT][AES-GCM ciphertext]
	payload := make([]byte, 4+len(kemCT)+len(ct))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(kemCT)))
	copy(payload[4:], kemCT)
	copy(payload[4+len(kemCT):], ct)

	var nonce24 [24]byte
	copy(nonce24[:], nonce12)

	return &EncryptResult{
		Nonce:   nonce24,
		Payload: payload,
		KeyData: skBytes,
	}, nil
}

func decryptPQC(skBytes, nonce24, payload []byte) ([]byte, error) {
	scheme := kyber768.Scheme()

	if len(skBytes) == 0 {
		return nil, fmt.Errorf("PQC: private key is empty — was the .key file for a PQC-encrypted file?")
	}

	sk, err := scheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("PQC: parse private key (%d bytes): %w", len(skBytes), err)
	}

	if len(payload) < 4 {
		return nil, fmt.Errorf("PQC: payload too short (%d bytes)", len(payload))
	}
	kemCTLen := int(binary.BigEndian.Uint32(payload[:4]))
	if len(payload) < 4+kemCTLen {
		return nil, fmt.Errorf("PQC: payload truncated (need %d, have %d)", 4+kemCTLen, len(payload))
	}
	kemCT := payload[4 : 4+kemCTLen]
	ciphertext := payload[4+kemCTLen:]

	ss, err := scheme.Decapsulate(sk, kemCT)
	if err != nil {
		return nil, fmt.Errorf("PQC: decapsulate failed — key file may not match this .dpec: %w", err)
	}
	if len(ss) < 32 {
		return nil, fmt.Errorf("PQC: decapsulated secret too short (%d bytes)", len(ss))
	}
	dek := ss[:32]

	nonce12 := nonce24[:12]
	plain, err := aesGCMDecrypt(dek, nonce12, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("PQC: AES-GCM authentication failed — data may be corrupt: %w", err)
	}
	return plain, nil
}
