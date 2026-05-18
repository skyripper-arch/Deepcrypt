package cmd

// ops.go — shared encrypt/decrypt pipeline used by both the CLI subcommands
// and the interactive TUI so logic is never duplicated.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"deepcrypt/internal/archive"
	dpecrypto "deepcrypt/internal/crypto"
	"deepcrypt/internal/entropy"
	"deepcrypt/internal/format"
	"deepcrypt/internal/hwid"
	"deepcrypt/internal/kdf"
	"deepcrypt/internal/settings"
)

// ErrPasswordRequired is returned by decryptTarget when the key file was
// encrypted with a password but none was supplied by the caller.
var ErrPasswordRequired = errors.New("password required")

// EncryptResult holds metadata produced by encryptTarget.
type EncryptResult struct {
	DCPPath  string
	KeyPath  string
	AlgoID   byte
	FileSize int64
	WasDir   bool
}

// encryptTarget encrypts a file or directory and writes a .dpec + .key pair.
// password may be empty if the user has not enabled password protection.
func encryptTarget(target, algoName string, b64Flag bool, password string) (*EncryptResult, error) {
	target = strings.Trim(target, `"' `)

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", target, err)
	}

	// Read plaintext (archive directory into gzip tar first).
	var plaintext []byte
	isDir := info.IsDir()
	if isDir {
		plaintext, err = archive.Pack(target)
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
	} else {
		plaintext, err = os.ReadFile(target)
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
	}

	// Per-file random session seed (stored in the .key file).
	sessionSeed := make([]byte, 32)
	if _, err := rand.Read(sessionSeed); err != nil {
		return nil, fmt.Errorf("session seed: %w", err)
	}

	// Load current settings to determine key-derivation mode.
	s := settings.Load()

	var material string
	var mlckBlk *format.MLCKBlock
	var keyMode byte

	if s.MachineLock.Enabled && s.MachineLock.ActiveCount() > 0 {
		// ── Machine-lock mode ────────────────────────────────────────────────
		keyMode = format.KeyModeLocked
		factors := hwid.Collect(
			s.MachineLock.SaveHWID,
			s.MachineLock.SaveNetwork,
			s.MachineLock.SaveMainboard,
			s.MachineLock.SaveProcessorID,
			s.MachineLock.SaveSerial,
		)
		material = "deepcrypt:locked|" + hwid.MaterialString(factors) + "|seed=" + hex.EncodeToString(sessionSeed)

		minReq := byte(settings.MinFactors)
		if int(minReq) > len(factors) {
			minReq = byte(len(factors))
		}
		mlckBlk = &format.MLCKBlock{MinRequired: minReq, HasPassword: password != ""}
		for _, f := range factors {
			mlckBlk.Factors = append(mlckBlk.Factors, format.StoredFactorHash{ID: f.ID, Hash: f.Hash})
		}
		if password != "" {
			pwSalt := make([]byte, 16)
			if _, err := rand.Read(pwSalt); err != nil {
				return nil, fmt.Errorf("pw salt: %w", err)
			}
			mlckBlk.PwSalt = pwSalt
			sum := sha256.Sum256(append([]byte(password), pwSalt...))
			material += "|pw=" + hex.EncodeToString(sum[:])
		}
	} else {
		// ── Shareable mode ───────────────────────────────────────────────────
		keyMode = format.KeyModeShareable
		material = "deepcrypt:shareable|seed=" + hex.EncodeToString(sessionSeed)
		if password != "" {
			pwSalt := make([]byte, 16)
			if _, err := rand.Read(pwSalt); err != nil {
				return nil, fmt.Errorf("pw salt: %w", err)
			}
			mlckBlk = &format.MLCKBlock{MinRequired: 0, HasPassword: true, PwSalt: pwSalt}
			sum := sha256.Sum256(append([]byte(password), pwSalt...))
			material += "|pw=" + hex.EncodeToString(sum[:])
		}
	}

	kdfResult, err := kdf.Derive(material, nil)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}

	algoID, err := dpecrypto.AlgoIDFromName(algoName)
	if err != nil {
		return nil, err
	}

	result, err := dpecrypto.Encrypt(algoID, kdfResult.Key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	// Build KeyData.  Symmetric ciphers use the new [mode|salt|seed|MLCK] layout.
	// Asymmetric ciphers keep their existing private-key layout unchanged.
	if format.IsSymmetric(algoID) {
		kd := []byte{keyMode}
		kd = append(kd, kdfResult.Salt...)
		kd = append(kd, sessionSeed...)
		if mlckBlk != nil {
			kd = append(kd, format.EncodeMlck(mlckBlk)...)
		}
		result.KeyData = kd
	}

	// Build flags.
	var flags byte
	if b64Flag {
		flags |= format.FlagBase64
	}
	if isDir {
		flags |= format.FlagIsDir
	}

	payload := result.Payload
	if b64Flag {
		payload = []byte(base64.StdEncoding.EncodeToString(payload))
	}

	// Output paths.
	// Files keep their original extension in the .dpec name so decryption can
	// restore it by stripping ".dpec" (e.g. video.mp4 → video.mp4.dpec → video.mp4).
	var baseName string
	var originalName string // stored in the key file for reliable extension recovery
	if isDir {
		baseName = filepath.Base(target)
	} else {
		baseName = filepath.Base(target) // e.g. "video.mp4"
		originalName = baseName
	}
	dir := filepath.Dir(target)
	dcpPath := filepath.Join(dir, baseName+".dpec")
	keyPath := filepath.Join(dir, baseName+".key")

	// Write .dpec.
	dcpFile, err := os.Create(dcpPath)
	if err != nil {
		return nil, fmt.Errorf("create .dpec: %w", err)
	}
	defer dcpFile.Close()

	hdr := &format.Header{AlgoID: algoID, Flags: flags, Nonce: result.Nonce}
	if err := format.WriteHeader(dcpFile, hdr); err != nil {
		return nil, err
	}
	if _, err := dcpFile.Write(payload); err != nil {
		return nil, err
	}

	// Write .key.
	kf, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("create .key: %w", err)
	}
	defer kf.Close()

	if err := format.WriteKeyFile(kf, &format.KeyFile{
		AlgoID:       algoID,
		KeyData:      result.KeyData,
		OriginalName: originalName,
	}); err != nil {
		return nil, err
	}

	fi, _ := os.Stat(dcpPath)
	return &EncryptResult{
		DCPPath:  dcpPath,
		KeyPath:  keyPath,
		AlgoID:   algoID,
		FileSize: fi.Size(),
		WasDir:   isDir,
	}, nil
}

// DecryptResult holds metadata produced by decryptTarget.
type DecryptResult struct {
	OutPath     string
	PlaintextSz int
	WasDir      bool
}

// decryptTarget decrypts a .dpec file using the paired .key file.
// password may be empty; ErrPasswordRequired is returned when the key file
// needs a password but none was provided.
func decryptTarget(dcpPath, keyPath, password string) (*DecryptResult, error) {
	dcpPath = strings.Trim(dcpPath, `"' `)
	keyPath = strings.Trim(keyPath, `"' `)

	// Parse .dpec header.
	dcpFile, err := os.Open(dcpPath)
	if err != nil {
		return nil, fmt.Errorf("open .dpec: %w", err)
	}
	defer dcpFile.Close()

	hdr, err := format.ReadHeader(dcpFile)
	if err != nil {
		return nil, err
	}

	rawPayload, err := io.ReadAll(dcpFile)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Base64 decode if flagged.
	payload := rawPayload
	if hdr.Flags&format.FlagBase64 != 0 {
		decoded, err := base64.StdEncoding.DecodeString(string(rawPayload))
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		payload = decoded
	}

	// Load .key file.
	kf, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer kf.Close()

	keyFile, err := format.ReadKeyFile(kf)
	if err != nil {
		return nil, err
	}

	if keyFile.AlgoID != hdr.AlgoID {
		return nil, fmt.Errorf("key algo (%s) does not match .dpec algo (%s)",
			format.AlgoName(keyFile.AlgoID), format.AlgoName(hdr.AlgoID))
	}

	// Re-derive key for symmetric ciphers.
	var derivedKey []byte
	if format.IsSymmetric(hdr.AlgoID) {
		derivedKey, err = rederiveSymmetricKey(keyFile.KeyData, password)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt.
	plaintext, err := dpecrypto.Decrypt(hdr.AlgoID, derivedKey, hdr.Nonce[:], payload, keyFile.KeyData)
	if err != nil {
		return nil, fmt.Errorf("decryption: %w", err)
	}

	// Determine output filename.
	// Priority: OriginalName from key file → strip ".dpec" from the .dpec filename.
	// Both methods preserve the original extension (e.g. video.mp4.dpec → video.mp4).
	outDir := filepath.Dir(dcpPath)
	var outBase string
	isArchive := hdr.Flags&format.FlagIsDir != 0
	if !isArchive && keyFile.OriginalName != "" {
		outBase = filepath.Join(outDir, keyFile.OriginalName)
	} else {
		// Strip exactly one ".dpec" suffix.
		stripped := strings.TrimSuffix(filepath.Base(dcpPath), ".dpec")
		outBase = filepath.Join(outDir, stripped)
	}

	if isArchive {
		if err := archive.Unpack(plaintext, outBase); err != nil {
			return nil, fmt.Errorf("extract archive: %w", err)
		}
	} else {
		if err := os.WriteFile(outBase, plaintext, 0644); err != nil {
			return nil, fmt.Errorf("write output: %w", err)
		}
	}

	return &DecryptResult{
		OutPath:     outBase,
		PlaintextSz: len(plaintext),
		WasDir:      isArchive,
	}, nil
}

// rederiveSymmetricKey reconstructs the 32-byte encryption key from KeyData.
//
// KeyData layouts:
//
//	Legacy (exactly 48 bytes): [16 argon2salt][32 session_seed]
//	  → key was derived from SerializeStable(HWID+IPs) + seed (old behaviour)
//
//	New (≥49 bytes): [1 mode][16 argon2salt][32 session_seed][optional MLCK]
//	  → mode 0x01 = shareable, mode 0x02 = machine-locked
func rederiveSymmetricKey(keyData []byte, password string) ([]byte, error) {
	// ── Legacy format ────────────────────────────────────────────────────────
	if len(keyData) == 48 {
		salt := keyData[:16]
		sessionSeed := keyData[16:48]
		bundle, err := entropy.Collect()
		if err != nil {
			return nil, fmt.Errorf("entropy: %w", err)
		}
		material := entropy.SerializeStable(bundle) + "|seed=" + hex.EncodeToString(sessionSeed)
		kdfResult, err := kdf.Derive(material, salt)
		if err != nil {
			return nil, fmt.Errorf("key re-derivation: %w", err)
		}
		return kdfResult.Key, nil
	}

	if len(keyData) < 49 {
		return nil, fmt.Errorf("key file corrupt: unexpected length %d", len(keyData))
	}

	// ── New format ───────────────────────────────────────────────────────────
	mode := keyData[0]
	salt := keyData[1:17]
	sessionSeed := keyData[17:49]

	// Parse optional MLCK block.
	var mlckBlk *format.MLCKBlock
	if len(keyData) > 49 {
		var err error
		mlckBlk, err = format.DecodeMlck(keyData[49:])
		if err != nil {
			return nil, fmt.Errorf("key file: %w", err)
		}
	}

	// Early-exit if password required but not provided.
	if mlckBlk != nil && mlckBlk.HasPassword && password == "" {
		return nil, ErrPasswordRequired
	}

	// Machine-lock verification.
	if mode == format.KeyModeLocked && mlckBlk != nil && len(mlckBlk.Factors) > 0 {
		stored := make([]hwid.StoredHash, len(mlckBlk.Factors))
		for i, f := range mlckBlk.Factors {
			stored[i] = hwid.StoredHash{ID: f.ID, Hash: f.Hash}
		}
		matches := hwid.CountMatching(stored)
		minReq := int(mlckBlk.MinRequired)
		if minReq == 0 {
			minReq = settings.MinFactors
		}
		if matches < minReq {
			return nil, fmt.Errorf("machine not authorised: %d/%d factors matched (need %d)",
				matches, len(mlckBlk.Factors), minReq)
		}
	}

	// Reconstruct the same material string used during encryption.
	var material string
	if mode == format.KeyModeLocked && mlckBlk != nil && len(mlckBlk.Factors) > 0 {
		ids := make([]byte, len(mlckBlk.Factors))
		for i, f := range mlckBlk.Factors {
			ids[i] = f.ID
		}
		factors := hwid.CollectByIDs(ids)
		material = "deepcrypt:locked|" + hwid.MaterialString(factors) + "|seed=" + hex.EncodeToString(sessionSeed)
	} else {
		material = "deepcrypt:shareable|seed=" + hex.EncodeToString(sessionSeed)
	}

	if mlckBlk != nil && mlckBlk.HasPassword && password != "" {
		sum := sha256.Sum256(append([]byte(password), mlckBlk.PwSalt...))
		material += "|pw=" + hex.EncodeToString(sum[:])
	}

	kdfResult, err := kdf.Derive(material, salt)
	if err != nil {
		return nil, fmt.Errorf("key re-derivation: %w", err)
	}
	return kdfResult.Key, nil
}

// peekNeedsPassword opens the key file and returns true when it contains a
// password-protected MLCK block.  Used by the interactive flow to ask for the
// password before starting the spinner.
func peekNeedsPassword(keyPath string) bool {
	keyPath = strings.Trim(keyPath, `"' `)
	f, err := os.Open(keyPath)
	if err != nil {
		return false
	}
	defer f.Close()
	kf, err := format.ReadKeyFile(f)
	if err != nil || len(kf.KeyData) <= 49 {
		return false
	}
	mlck, err := format.DecodeMlck(kf.KeyData[49:])
	return err == nil && mlck.HasPassword
}
