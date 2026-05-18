package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// MinFactors is the minimum number of hardware factors that must match
// on the decrypting machine when machine lock is active.
const MinFactors = 3

// MachineLock controls which hardware identifiers are bound into the key.
type MachineLock struct {
	Enabled         bool `json:"enabled"`
	SaveHWID        bool `json:"save_hwid"`
	SaveNetwork     bool `json:"save_network"`
	SaveMainboard   bool `json:"save_mainboard"`
	SaveProcessorID bool `json:"save_processor_id"`
	SaveSerial      bool `json:"save_serial"`
}

// ActiveCount returns how many individual factor options are switched on.
func (m MachineLock) ActiveCount() int {
	n := 0
	for _, v := range []bool{m.SaveHWID, m.SaveNetwork, m.SaveMainboard, m.SaveProcessorID, m.SaveSerial} {
		if v {
			n++
		}
	}
	return n
}

// Settings is the top-level config persisted to disk.
type Settings struct {
	MachineLock MachineLock `json:"machine_lock"`
	UsePassword bool        `json:"use_password"`
}

// Default returns factory-default settings (shareable keys, no password).
func Default() *Settings { return &Settings{} }

// Load reads settings from disk. Returns Default() on any error.
func Load() *Settings {
	p, err := configPath()
	if err != nil {
		return Default()
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return Default()
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Default()
	}
	return &s
}

// Save writes settings to disk, creating the config directory if needed.
func (s *Settings) Save() error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "deepcrypt", "settings.json"), nil
}
