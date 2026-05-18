package crypto

import (
	"fmt"
	"strings"
)

// Lua-XOR obfuscation: XOR-streams bytes with the derived key then formats the
// result as a Lua string.char() expression.  Trivially reversible by anyone
// who has the key file — treat as obfuscation, not encryption (green tier).
func encryptLuac(derivedKey, plaintext []byte) (*EncryptResult, error) {
	xored := xorStream(plaintext, derivedKey)

	var sb strings.Builder
	sb.WriteString("--[[dpc:luac:v1]]\nlocal d=string.char(")
	for i, b := range xored {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "0x%02X", b)
	}
	sb.WriteString(") return d")

	return &EncryptResult{Payload: []byte(sb.String())}, nil
}

func decryptLuac(derivedKey, _ /*nonce*/, ciphertext []byte) ([]byte, error) {
	s := string(ciphertext)

	const open = "string.char("
	start := strings.Index(s, open)
	if start == -1 {
		return nil, fmt.Errorf("luac: missing string.char marker")
	}
	start += len(open)

	end := strings.LastIndex(s, ")")
	if end <= start {
		return nil, fmt.Errorf("luac: malformed payload")
	}

	parts := strings.Split(s[start:end], ",")
	xored := make([]byte, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		var b uint64
		if _, err := fmt.Sscanf(p, "0x%X", &b); err != nil {
			return nil, fmt.Errorf("luac: parse byte %d %q: %w", i, p, err)
		}
		xored[i] = byte(b)
	}

	return xorStream(xored, derivedKey), nil
}

// xorStream XORs src with key repeated cyclically.
func xorStream(src, key []byte) []byte {
	out := make([]byte, len(src))
	for i, b := range src {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}
