package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic    = "DPEC"
	KeyMagic = "DKEY"

	AlgoAES      = byte(0x01)
	AlgoChaCha   = byte(0x02)
	AlgoRSA      = byte(0x03)
	AlgoECC      = byte(0x04)
	AlgoPQC      = byte(0x05)
	AlgoTwofish  = byte(0x06)
	AlgoBlowfish = byte(0x07)
	Algo3DES     = byte(0x08)
	AlgoDES      = byte(0x09)
	AlgoBase64   = byte(0x0A)
	AlgoLuac     = byte(0x0B)

	// Flags byte (B64Flag field): bitmask
	FlagBase64 = byte(0x01) // bit 0: payload is base64-encoded
	FlagIsDir  = byte(0x02) // bit 1: payload decrypts to a gzipped tar archive

	NonceLen  = 24
	HeaderLen = 4 + 1 + 1 + NonceLen // 30 bytes

	// KeyData mode byte (first byte of new-format KeyData for symmetric algos).
	// Legacy keys (exactly 48 bytes) predate this field and use HWID-bound derivation.
	KeyModeShareable = byte(0x01) // no machine binding — key file is shareable
	KeyModeLocked    = byte(0x02) // machine-lock — selected hardware factors required

	mlckMagic       = "MLCK"
	MLCKFlagPassword = byte(0x01) // bit 0: a password was mixed into the key derivation
)

// StoredFactorHash is a 33-byte record stored in an MLCK block:
// [1 byte factor ID][32 bytes SHA-256 of factor value].
type StoredFactorHash struct {
	ID   byte
	Hash [32]byte
}

// MLCKBlock is the machine-lock extension appended to symmetric KeyData.
// It carries the hardware hashes needed to verify the decrypting machine
// and the password salt when a password was used.
type MLCKBlock struct {
	MinRequired byte
	HasPassword bool
	Factors     []StoredFactorHash
	PwSalt      []byte // 16 bytes, present only when HasPassword is true
}

// EncodeMlck serialises b to a byte slice.
func EncodeMlck(b *MLCKBlock) []byte {
	var flags byte
	if b.HasPassword {
		flags |= MLCKFlagPassword
	}
	buf := make([]byte, 0, 8+len(b.Factors)*33+16)
	buf = append(buf, []byte(mlckMagic)...)
	buf = append(buf, 0x01)                  // version
	buf = append(buf, flags)                  // flags
	buf = append(buf, byte(len(b.Factors)))   // N
	buf = append(buf, b.MinRequired)          // min_required
	for _, f := range b.Factors {
		buf = append(buf, f.ID)
		buf = append(buf, f.Hash[:]...)
	}
	if b.HasPassword && len(b.PwSalt) == 16 {
		buf = append(buf, b.PwSalt...)
	}
	return buf
}

// DecodeMlck parses an MLCK block from raw bytes.
func DecodeMlck(data []byte) (*MLCKBlock, error) {
	if len(data) < 8 || string(data[:4]) != mlckMagic {
		return nil, fmt.Errorf("format: not an MLCK block")
	}
	// data[4] = version (ignored for now)
	flags := data[5]
	n := int(data[6])
	minReq := data[7]

	need := 8 + n*33
	if flags&MLCKFlagPassword != 0 {
		need += 16
	}
	if len(data) < need {
		return nil, fmt.Errorf("format: MLCK block too short (need %d, got %d)", need, len(data))
	}

	blk := &MLCKBlock{MinRequired: minReq, HasPassword: flags&MLCKFlagPassword != 0}
	off := 8
	for i := 0; i < n; i++ {
		var h [32]byte
		copy(h[:], data[off+1:off+33])
		blk.Factors = append(blk.Factors, StoredFactorHash{ID: data[off], Hash: h})
		off += 33
	}
	if blk.HasPassword {
		blk.PwSalt = make([]byte, 16)
		copy(blk.PwSalt, data[off:off+16])
	}
	return blk, nil
}

// Header is the fixed 30-byte prefix of every .dcp file.
type Header struct {
	AlgoID  byte
	Flags   byte
	Nonce   [NonceLen]byte
}

func WriteHeader(w io.Writer, h *Header) error {
	if _, err := w.Write([]byte(Magic)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{h.AlgoID, h.Flags}); err != nil {
		return err
	}
	_, err := w.Write(h.Nonce[:])
	return err
}

func ReadHeader(r io.Reader) (*Header, error) {
	buf := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("format: read header: %w", err)
	}
	if !bytes.Equal(buf[:4], []byte(Magic)) {
		return nil, fmt.Errorf("format: invalid magic — not a .dcp file")
	}
	h := &Header{AlgoID: buf[4], Flags: buf[5]}
	copy(h.Nonce[:], buf[6:])
	return h, nil
}

// KeyFile is the structure stored in the .key file.
// For symmetric ciphers KeyData = mode byte + Argon2id salt + session seed + optional MLCK block.
// For asymmetric ciphers KeyData = serialized private key.
// OriginalName stores the original filename (e.g. "video.mp4") so decrypt can restore the extension.
type KeyFile struct {
	AlgoID       byte
	KeyData      []byte
	OriginalName string // original filename with extension; empty for directory archives
}

// key file layout:
//
//	[4] "DKEY" magic
//	[1] algo_id
//	[4] key_data length  (big-endian)
//	[N] key_data
//	[4] "ORIG" magic     (optional section — absent in legacy files)
//	[4] name length
//	[N] original filename bytes (UTF-8)
const origMagic = "ORIG"

func WriteKeyFile(w io.Writer, kf *KeyFile) error {
	if _, err := w.Write([]byte(KeyMagic)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{kf.AlgoID}); err != nil {
		return err
	}
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(kf.KeyData)))
	if _, err := w.Write(lb[:]); err != nil {
		return err
	}
	if _, err := w.Write(kf.KeyData); err != nil {
		return err
	}
	// Optional ORIG section — write only when a name is available.
	if kf.OriginalName != "" {
		if _, err := w.Write([]byte(origMagic)); err != nil {
			return err
		}
		nb := []byte(kf.OriginalName)
		binary.BigEndian.PutUint32(lb[:], uint32(len(nb)))
		if _, err := w.Write(lb[:]); err != nil {
			return err
		}
		if _, err := w.Write(nb); err != nil {
			return err
		}
	}
	return nil
}

func ReadKeyFile(r io.Reader) (*KeyFile, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("format: key read: %w", err)
	}
	if !bytes.Equal(magic, []byte(KeyMagic)) {
		return nil, fmt.Errorf("format: invalid key file magic")
	}
	var hdr [5]byte // [1]algo_id [4]len
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("format: key header read: %w", err)
	}
	dataLen := binary.BigEndian.Uint32(hdr[1:])
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("format: key data read: %w", err)
	}
	kf := &KeyFile{AlgoID: hdr[0], KeyData: data}

	// Attempt to read the optional ORIG section — EOF here is fine.
	var tagBuf [4]byte
	if _, err := io.ReadFull(r, tagBuf[:]); err == nil && string(tagBuf[:]) == origMagic {
		var nlenBuf [4]byte
		if _, err := io.ReadFull(r, nlenBuf[:]); err == nil {
			nameLen := binary.BigEndian.Uint32(nlenBuf[:])
			if nameLen > 0 && nameLen < 4096 {
				nb := make([]byte, nameLen)
				if _, err := io.ReadFull(r, nb); err == nil {
					kf.OriginalName = string(nb)
				}
			}
		}
	}

	return kf, nil
}

func AlgoName(id byte) string {
	switch id {
	case AlgoAES:
		return "AES-256-GCM"
	case AlgoChaCha:
		return "XChaCha20-Poly1305"
	case AlgoRSA:
		return "RSA-4096-OAEP"
	case AlgoECC:
		return "ECC/Curve25519"
	case AlgoPQC:
		return "ML-KEM-768 (PQC)"
	case AlgoTwofish:
		return "Twofish-256-CBC"
	case AlgoBlowfish:
		return "Blowfish-448-CBC"
	case Algo3DES:
		return "3DES (Triple-DES)"
	case AlgoDES:
		return "DES-CBC"
	case AlgoBase64:
		return "Base64 (encoding only)"
	case AlgoLuac:
		return "Lua-XOR (obfuscation)"
	default:
		return fmt.Sprintf("unknown(0x%02x)", id)
	}
}

// IsSymmetric reports whether algoID uses Argon2id key derivation.
// Asymmetric ciphers (RSA, ECC, PQC) generate their own key pairs.
func IsSymmetric(id byte) bool {
	switch id {
	case AlgoRSA, AlgoECC, AlgoPQC:
		return false
	}
	return true
}
