package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// pkcs7Pad pads b to the next multiple of blockSize using PKCS#7.
func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	padded := make([]byte, len(b)+n)
	copy(padded, b)
	for i := len(b); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding and validates it.
func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid length %d", len(b))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, fmt.Errorf("pkcs7: bad padding byte %d", n)
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil, fmt.Errorf("pkcs7: inconsistent padding")
		}
	}
	return b[:len(b)-n], nil
}

// cbcEncryptWithIV encrypts plaintext with CBC, writing the IV into nonce24[0:ivLen].
// Returns the ciphertext (without IV) and the populated nonce24.
func cbcEncryptWithIV(block cipher.Block, plaintext []byte) ([24]byte, []byte, error) {
	ivLen := block.BlockSize()
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return [24]byte{}, nil, fmt.Errorf("CBC: IV: %w", err)
	}
	padded := pkcs7Pad(plaintext, ivLen)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	var nonce24 [24]byte
	copy(nonce24[:], iv)
	return nonce24, ct, nil
}

// cbcDecryptWithIV decrypts ciphertext using the IV from nonce24[0:blockSize].
func cbcDecryptWithIV(block cipher.Block, nonce24, ciphertext []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, fmt.Errorf("CBC: invalid ciphertext length %d", len(ciphertext))
	}
	iv := nonce24[:bs]
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return pkcs7Unpad(plain, bs)
}
