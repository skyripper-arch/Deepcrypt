// Package entropy collects multi-source system telemetry used as high-entropy
// input material for Argon2id master-key derivation.
//
// Collection pipeline:
//  1. HWID  — hardware-bound unique identifier (motherboard UUID / machine-id)
//  2. IPs   — active non-loopback interface addresses (network snapshot)
//  3. RAM   — approximate free kernel memory in KB (volatile)
//  4. Time  — current wall-clock time in nanoseconds (volatile)
//  5. Up    — system uptime in nanoseconds (volatile)
//  6. Rand  — 32 bytes from the OS CSPRNG (unconditional cryptographic noise)
package entropy

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Bundle holds every collected entropy source before serialization.
type Bundle struct {
	HWID        string
	LocalIPs    []string
	FreeRAMKB   uint64
	TimestampNs int64
	UptimeNs    int64
	RandSeed    []byte // 32 bytes of CSPRNG output
}

// Collect gathers system telemetry from all available entropy sources.
// Individual source failures are non-fatal; a sentinel value is substituted
// so that key derivation still proceeds with the remaining material.
func Collect() (*Bundle, error) {
	b := &Bundle{
		TimestampNs: time.Now().UnixNano(),
	}

	hwid, err := getHWID()
	if err != nil {
		hwid = "hwid-unavailable"
	}
	b.HWID = hwid

	ips, err := getLocalIPs()
	if err != nil || len(ips) == 0 {
		ips = []string{"ip-unavailable"}
	}
	b.LocalIPs = ips

	b.FreeRAMKB = getFreeRAMKB()
	b.UptimeNs = getUptimeNs()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("entropy: CSPRNG read failed: %w", err)
	}
	b.RandSeed = seed

	return b, nil
}

// Serialize encodes all bundle fields into a single pipe-delimited string.
// Includes volatile metrics — useful for logging/audit but NOT for key
// derivation (volatile values change between calls).
func Serialize(b *Bundle) string {
	parts := []string{
		b.HWID,
		strings.Join(b.LocalIPs, ","),
		fmt.Sprintf("ram=%d", b.FreeRAMKB),
		fmt.Sprintf("ts=%d", b.TimestampNs),
		fmt.Sprintf("up=%d", b.UptimeNs),
		fmt.Sprintf("rng=%x", b.RandSeed),
	}
	return strings.Join(parts, "|")
}

// SerializeStable returns only the hardware-stable fields (HWID + network
// interfaces). This string is reproducible on the same machine across calls
// and is safe to use as Argon2id password material for HWID-bound keys.
func SerializeStable(b *Bundle) string {
	return b.HWID + "|" + strings.Join(b.LocalIPs, ",")
}

// ─── HWID ────────────────────────────────────────────────────────────────────

func getHWID() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return getHWIDWindows()
	case "linux":
		return getHWIDLinux()
	case "darwin":
		return getHWIDDarwin()
	default:
		return "platform-unknown", nil
	}
}

func getHWIDWindows() (string, error) {
	// Primary: PowerShell Get-CimInstance (wmic deprecated/removed in Windows 10+)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -First 1).UUID").Output()
	if err == nil {
		uuid := strings.TrimSpace(string(out))
		if uuid != "" && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" &&
			uuid != "00000000-0000-0000-0000-000000000000" {
			return uuid, nil
		}
	}

	// Fallback 1: legacy wmic (Windows 7/8 compatibility)
	out, err = exec.Command("wmic", "csproduct", "get", "UUID", "/value").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
			if strings.HasPrefix(line, "UUID=") {
				uuid := strings.TrimPrefix(line, "UUID=")
				if uuid != "" && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
					return uuid, nil
				}
			}
		}
	}

	// Fallback 2: MachineGuid registry key — stable across reboots
	out, err = exec.Command(
		"reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid",
	).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
			if strings.Contains(line, "MachineGuid") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[len(fields)-1], nil
				}
			}
		}
	}

	// Fallback 3: CPU ProcessorId via PowerShell
	out, err = exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).ProcessorId").Output()
	if err == nil {
		id := strings.TrimSpace(string(out))
		if id != "" && id != "0000000000000000" {
			return id, nil
		}
	}

	return "", fmt.Errorf("windows HWID: all collection methods failed")
}

func getHWIDLinux() (string, error) {
	// Android (Termux) reports GOOS=linux but has getprop instead of machine-id
	if out, err := exec.Command("getprop", "ro.build.id").Output(); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			for _, prop := range []string{"ro.serialno", "ro.boot.serialno", "ro.build.fingerprint"} {
				if v, err2 := exec.Command("getprop", prop).Output(); err2 == nil {
					if id := strings.TrimSpace(string(v)); id != "" {
						return id, nil
					}
				}
			}
		}
	}

	// Standard Linux: /etc/machine-id — written by systemd, readable without root.
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(p)
		if err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id, nil
			}
		}
	}

	// Fallback: DMI product UUID (requires root on most kernels).
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}

	return "", fmt.Errorf("linux HWID: no readable identifier found")
}

func getHWIDDarwin() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("darwin HWID: ioreg failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				uuid := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				if uuid != "" {
					return uuid, nil
				}
			}
		}
	}
	return "", fmt.Errorf("darwin HWID: IOPlatformUUID not found in ioreg output")
}

// ─── Network Snapshot ────────────────────────────────────────────────────────

func getLocalIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, iface := range ifaces {
		// Skip loopback and down interfaces.
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

// ─── Volatile System Metrics ─────────────────────────────────────────────────

func getFreeRAMKB() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// Sys is total OS-allocated bytes; HeapInuse is currently in-use heap.
	// Their difference is a coarse proxy for available runtime memory.
	if ms.Sys > ms.HeapInuse {
		return (ms.Sys - ms.HeapInuse) / 1024
	}
	return 0
}

func getUptimeNs() int64 {
	// Linux: parse /proc/uptime for seconds since boot.
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			var seconds float64
			if _, err := fmt.Sscanf(string(data), "%f", &seconds); err == nil {
				return int64(seconds * 1e9)
			}
		}
	}
	// All other platforms: monotonic nanoseconds since process start.
	// Not true uptime, but still captures volatile machine state.
	return time.Now().UnixNano()
}
