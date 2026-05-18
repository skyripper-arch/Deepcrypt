// Package kdf wraps Argon2id key derivation as specified:
// time=3, memory=64 MB, threads=4, output=32 bytes (256-bit).
package kdf

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime    uint32 = 3
	ArgonMemory  uint32 = 64 * 1024 // 64 MB expressed in KB
	ArgonThreads uint8  = 4
	ArgonKeyLen  uint32 = 32 // 256-bit output
	SaltLen             = 16 // 128-bit salt
)

// Result holds the derived key and the salt that produced it.
// Both must be stored alongside the encrypted payload so decryption
// can re-derive the same key from the same entropy material.
type Result struct {
	Key  []byte // 32 bytes
	Salt []byte // SaltLen bytes
}

// Derive runs Argon2id over entropyMaterial using the given salt.
// If salt is nil, a fresh cryptographically random salt is generated.
func Derive(entropyMaterial string, salt []byte) (*Result, error) {
	if len(entropyMaterial) == 0 {
		return nil, fmt.Errorf("kdf: empty entropy material")
	}

	if salt == nil {
		salt = make([]byte, SaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("kdf: salt generation failed: %w", err)
		}
	}

	key := argon2.IDKey(
		[]byte(entropyMaterial),
		salt,
		ArgonTime,
		ArgonMemory,
		ArgonThreads,
		ArgonKeyLen,
	)

	return &Result{Key: key, Salt: salt}, nil
}
