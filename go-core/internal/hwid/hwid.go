// Package hwid collects individual hardware fingerprints used for
// machine-lock key binding.  Each factor is collected independently so
// the user can choose which ones to embed in the key file.
package hwid

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// Factor type IDs stored in the MLCK block.
const (
	FactorHWID        = byte(0x01) // motherboard / product UUID
	FactorNetwork     = byte(0x02) // local IP addresses
	FactorMainboard   = byte(0x03) // mainboard serial / model
	FactorProcessorID = byte(0x04) // CPU processor identifier
	FactorSerial      = byte(0x05) // BIOS system serial number
)

// Factor is a single hardware fingerprint with its SHA-256 hash.
type Factor struct {
	ID   byte
	Hash [32]byte
	Raw  string
}

// StoredHash is a compact record (ID + SHA-256) as stored in the key file.
type StoredHash struct {
	ID   byte
	Hash [32]byte
}

// Collect gathers the selected hardware factors in a stable (sorted) order.
func Collect(wHWID, wNetwork, wMainboard, wProcessorID, wSerial bool) []*Factor {
	type item struct {
		id  byte
		fn  func() string
		use bool
	}
	all := []item{
		{FactorHWID, getHWID, wHWID},
		{FactorNetwork, getNetwork, wNetwork},
		{FactorMainboard, getMainboard, wMainboard},
		{FactorProcessorID, getProcessorID, wProcessorID},
		{FactorSerial, getSerial, wSerial},
	}
	var out []*Factor
	for _, it := range all {
		if !it.use {
			continue
		}
		raw := it.fn()
		h := sha256.Sum256([]byte(raw))
		out = append(out, &Factor{ID: it.id, Hash: h, Raw: raw})
	}
	return out
}

// CollectByIDs re-collects factors for a specific set of IDs (e.g. from the key file).
// Results are returned in ascending ID order for deterministic material strings.
func CollectByIDs(ids []byte) []*Factor {
	sorted := make([]byte, len(ids))
	copy(sorted, ids)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var out []*Factor
	for _, id := range sorted {
		var raw string
		switch id {
		case FactorHWID:
			raw = getHWID()
		case FactorNetwork:
			raw = getNetwork()
		case FactorMainboard:
			raw = getMainboard()
		case FactorProcessorID:
			raw = getProcessorID()
		case FactorSerial:
			raw = getSerial()
		default:
			continue
		}
		h := sha256.Sum256([]byte(raw))
		out = append(out, &Factor{ID: id, Hash: h, Raw: raw})
	}
	return out
}

// CountMatching returns how many of the stored hashes match the current machine.
func CountMatching(stored []StoredHash) int {
	n := 0
	for _, s := range stored {
		var raw string
		switch s.ID {
		case FactorHWID:
			raw = getHWID()
		case FactorNetwork:
			raw = getNetwork()
		case FactorMainboard:
			raw = getMainboard()
		case FactorProcessorID:
			raw = getProcessorID()
		case FactorSerial:
			raw = getSerial()
		default:
			continue
		}
		if sha256.Sum256([]byte(raw)) == s.Hash {
			n++
		}
	}
	return n
}

// MaterialString returns a deterministic pipe-delimited string from the given
// factors, suitable as Argon2id password material.
func MaterialString(factors []*Factor) string {
	parts := make([]string, len(factors))
	for i, f := range factors {
		parts[i] = fmt.Sprintf("%d=%s", f.ID, f.Raw)
	}
	return strings.Join(parts, "|")
}

// ─── per-factor collectors ────────────────────────────────────────────────────

func getHWID() string {
	switch runtime.GOOS {
	case "windows":
		// Primary: PowerShell Get-CimInstance (wmic deprecated in Windows 10+)
		if v := cimGet("Win32_ComputerSystemProduct", "UUID"); isUsable(v) {
			return v
		}
		// Fallback: legacy wmic (Windows 7/8)
		if v := wmicGet("csproduct", "UUID"); isUsable(v) {
			return v
		}
		// Last resort: stable registry MachineGuid written by Windows Setup
		if v := regValue(`HKLM\SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); v != "" {
			return v
		}
	case "linux":
		// Android (Termux) reports GOOS=linux but has getprop instead of machine-id
		if isAndroid() {
			for _, prop := range []string{"ro.serialno", "ro.boot.serialno", "ro.build.fingerprint"} {
				if v := getProp(prop); v != "" {
					return v
				}
			}
		}
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if v := fileContent(p); v != "" {
				return v
			}
		}
		// Requires root on most kernels, but try anyway
		if v := fileContent("/sys/class/dmi/id/product_uuid"); isUsable(v) {
			return v
		}
	case "android":
		for _, prop := range []string{"ro.serialno", "ro.boot.serialno", "ro.build.fingerprint"} {
			if v := getProp(prop); v != "" {
				return v
			}
		}
	case "darwin":
		if v := ioregField("IOPlatformUUID"); v != "" {
			return v
		}
	}
	return "hwid-unavailable"
}

func getNetwork() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "network-unavailable"
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		return "network-no-ips"
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

func getMainboard() string {
	switch runtime.GOOS {
	case "windows":
		// PowerShell CIM (preferred over deprecated wmic)
		if v := cimGet("Win32_BaseBoard", "SerialNumber"); isUsable(v) {
			return v
		}
		if v := cimGet("Win32_BaseBoard", "Product"); isUsable(v) {
			return v
		}
		// Legacy wmic fallbacks
		if v := wmicGet("baseboard", "SerialNumber"); isUsable(v) {
			return v
		}
		if v := wmicGet("baseboard", "Product"); isUsable(v) {
			return v
		}
	case "linux":
		if isAndroid() {
			if v := getProp("ro.product.board"); v != "" {
				return v
			}
			if v := getProp("ro.hardware"); v != "" {
				return v
			}
		}
		if v := fileContent("/sys/class/dmi/id/board_serial"); isUsable(v) {
			return v
		}
		if v := fileContent("/sys/class/dmi/id/board_name"); isUsable(v) {
			return v
		}
		if v := fileContent("/sys/class/dmi/id/board_vendor"); isUsable(v) {
			return v
		}
	case "android":
		if v := getProp("ro.product.board"); v != "" {
			return v
		}
		if v := getProp("ro.hardware"); v != "" {
			return v
		}
	case "darwin":
		if v := sysctlVal("hw.model"); v != "" {
			return v
		}
	}
	return "mainboard-unavailable"
}

func getProcessorID() string {
	switch runtime.GOOS {
	case "windows":
		// PowerShell CIM (preferred)
		if v := cimGet("Win32_Processor", "ProcessorId"); isUsable(v) {
			return v
		}
		// Legacy wmic fallback
		if v := wmicGet("cpu", "ProcessorId"); isUsable(v) {
			return v
		}
	case "linux":
		if isAndroid() {
			// SoC chip name + hardware + ABI gives a stable device fingerprint
			var parts []string
			for _, prop := range []string{"ro.chipname", "ro.hardware", "ro.product.cpu.abi"} {
				if v := getProp(prop); v != "" {
					parts = append(parts, v)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "/")
			}
		}
		data, _ := os.ReadFile("/proc/cpuinfo")
		// ARM/RPi boards expose a unique "Serial" field
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.ToLower(line), "serial") {
				if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
					if v := strings.TrimSpace(parts[1]); isUsable(v) {
						return v
					}
				}
			}
		}
		// x86 fallback: model name (stable per machine, not globally unique)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.ToLower(line), "model name") {
				if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
					if v := strings.TrimSpace(parts[1]); v != "" {
						return v
					}
				}
			}
		}
	case "android":
		var parts []string
		for _, prop := range []string{"ro.chipname", "ro.hardware", "ro.product.cpu.abi"} {
			if v := getProp(prop); v != "" {
				parts = append(parts, v)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "/")
		}
	case "darwin":
		if v := sysctlVal("machdep.cpu.brand_string"); v != "" {
			return v
		}
	}
	return "processorid-unavailable"
}

func getSerial() string {
	switch runtime.GOOS {
	case "windows":
		// PowerShell CIM (preferred)
		if v := cimGet("Win32_BIOS", "SerialNumber"); isUsable(v) {
			return v
		}
		// Legacy wmic fallback
		if v := wmicGet("bios", "SerialNumber"); isUsable(v) {
			return v
		}
	case "linux":
		if isAndroid() {
			for _, prop := range []string{"ro.serialno", "ro.boot.serialno"} {
				if v := getProp(prop); v != "" {
					return v
				}
			}
		}
		if v := fileContent("/sys/class/dmi/id/product_serial"); isUsable(v) {
			return v
		}
		if v := fileContent("/sys/class/dmi/id/chassis_serial"); isUsable(v) {
			return v
		}
	case "android":
		for _, prop := range []string{"ro.serialno", "ro.boot.serialno"} {
			if v := getProp(prop); v != "" {
				return v
			}
		}
	case "darwin":
		out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "Serial Number") {
					if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return "serial-unavailable"
}

// ─── OS helpers ───────────────────────────────────────────────────────────────

// cimGet fetches a single WMI/CIM property via PowerShell — replaces deprecated wmic.
func cimGet(class, prop string) string {
	expr := fmt.Sprintf("(Get-CimInstance -ClassName %s | Select-Object -First 1).%s", class, prop)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", expr).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// wmicGet is the legacy WMIC fallback for Windows 7/8 compatibility.
func wmicGet(class, field string) string {
	out, err := exec.Command("wmic", class, "get", field, "/value").Output()
	if err != nil {
		return ""
	}
	prefix := strings.ToUpper(field) + "="
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if strings.HasPrefix(strings.ToUpper(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

// getProp reads an Android system property via getprop.
func getProp(key string) string {
	out, err := exec.Command("getprop", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// isAndroid returns true when running inside Android or Termux.
// runtime.GOOS == "linux" on Termux, so we probe for getprop.
func isAndroid() bool {
	out, err := exec.Command("getprop", "ro.build.id").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func regValue(key, value string) string {
	out, err := exec.Command("reg", "query", key, "/v", value).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), strings.ToLower(value)) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1]
			}
		}
	}
	return ""
}

func fileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ioregField(fieldName string) string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, fieldName) {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				return strings.Trim(strings.TrimSpace(parts[1]), `"`)
			}
		}
	}
	return ""
}

func sysctlVal(key string) string {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func isUsable(v string) bool {
	if v == "" {
		return false
	}
	bad := []string{
		"Default string",
		"To be filled by O.E.M.",
		"Not Specified",
		"N/A",
		"None",
		"0000000000000000",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
	}
	for _, b := range bad {
		if strings.EqualFold(v, b) {
			return false
		}
	}
	return true
}
