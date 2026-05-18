// Package crypto implements all Deepcrypt cipher suites and dispatches
// encrypt/decrypt calls based on the algorithm ID from the .dpec header.
package crypto

import "fmt"

// EncryptResult carries everything produced during encryption.
// Nonce   → stored verbatim in the .dpec header (24 bytes).
// Payload → written as the .dpec body.
// KeyData → written to the .key file.
//   Symmetric (AES, ChaCha, Twofish, Blowfish, 3DES, DES, B64, Luac): Argon2id salt (16 bytes).
//   Asymmetric (RSA, ECC, PQC): serialised private key.
type EncryptResult struct {
	Nonce   [24]byte
	Payload []byte
	KeyData []byte
}

// Encrypt dispatches to the correct cipher.
// derivedKey: 32-byte Argon2id output — used by all symmetric ciphers.
// For asymmetric ciphers it is ignored; a fresh key pair is generated.
func Encrypt(algoID byte, derivedKey, plaintext []byte) (*EncryptResult, error) {
	switch algoID {
	case 0x01:
		return encryptAES(derivedKey, plaintext)
	case 0x02:
		return encryptChaCha(derivedKey, plaintext)
	case 0x03:
		return encryptRSA(plaintext)
	case 0x04:
		return encryptECC(plaintext)
	case 0x05:
		return encryptPQC(plaintext)
	case 0x06:
		return encryptTwofish(derivedKey, plaintext)
	case 0x07:
		return encryptBlowfish(derivedKey, plaintext)
	case 0x08:
		return encrypt3DES(derivedKey, plaintext)
	case 0x09:
		return encryptDES(derivedKey, plaintext)
	case 0x0A:
		return encryptB64(derivedKey, plaintext)
	case 0x0B:
		return encryptLuac(derivedKey, plaintext)
	default:
		return nil, fmt.Errorf("crypto: unknown algo ID 0x%02x", algoID)
	}
}

// Decrypt dispatches to the correct cipher.
// derivedKey: re-derived Argon2id key — used by all symmetric ciphers.
// nonce:      24-byte nonce field from the .dpec header (also carries CBC IVs).
// payload:    raw (already base64-decoded) .dpec body.
// keyData:    contents of the .key file (salt for symmetric, private key for asymmetric).
func Decrypt(algoID byte, derivedKey, nonce, payload, keyData []byte) ([]byte, error) {
	switch algoID {
	case 0x01:
		return decryptAES(derivedKey, nonce, payload)
	case 0x02:
		return decryptChaCha(derivedKey, nonce, payload)
	case 0x03:
		return decryptRSA(keyData, nonce, payload)
	case 0x04:
		return decryptECC(keyData, nonce, payload)
	case 0x05:
		return decryptPQC(keyData, nonce, payload)
	case 0x06:
		return decryptTwofish(derivedKey, nonce, payload)
	case 0x07:
		return decryptBlowfish(derivedKey, nonce, payload)
	case 0x08:
		return decrypt3DES(derivedKey, nonce, payload)
	case 0x09:
		return decryptDES(derivedKey, nonce, payload)
	case 0x0A:
		return decryptB64(derivedKey, nonce, payload)
	case 0x0B:
		return decryptLuac(derivedKey, nonce, payload)
	default:
		return nil, fmt.Errorf("crypto: unknown algo ID 0x%02x", algoID)
	}
}

// AlgoIDFromName maps a CLI flag string to a header byte.
func AlgoIDFromName(name string) (byte, error) {
	switch name {
	case "aes":
		return 0x01, nil
	case "chacha":
		return 0x02, nil
	case "rsa":
		return 0x03, nil
	case "ecc":
		return 0x04, nil
	case "pqc":
		return 0x05, nil
	case "twofish":
		return 0x06, nil
	case "blowfish":
		return 0x07, nil
	case "3des":
		return 0x08, nil
	case "des":
		return 0x09, nil
	case "b64":
		return 0x0A, nil
	case "luac":
		return 0x0B, nil
	default:
		return 0, fmt.Errorf("crypto: unknown algorithm %q", name)
	}
}
