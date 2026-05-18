package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type testCase struct {
	name string
	algo string
	icon string
	tier string // "red" | "yellow" | "green"
}

var cipherTests = []testCase{
	{"ML-KEM-768 (PQC)    ", "pqc", "⚛ ", "red"},
	{"AES-256-GCM         ", "aes", "🛡 ", "red"},
	{"XChaCha20-Poly1305  ", "chacha", "💨", "red"},
	{"RSA-4096-OAEP       ", "rsa", "🔑", "red"},
	{"ECC / Curve25519    ", "ecc", "〰 ", "red"},
	{"Twofish-256-CBC     ", "twofish", "🐟", "red"},
	{"Blowfish-448-CBC    ", "blowfish", "🐡", "yellow"},
	{"3DES (Triple-DES)   ", "3des", "🔐", "yellow"},
	{"DES-CBC             ", "des", "🔓", "green"},
	{"Base64              ", "b64", "📝", "green"},
	{"Lua-XOR             ", "luac", "📜", "green"},
}

func newTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run round-trip tests on all cipher suites",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			runAllTests()
		},
	}
}

func runAllTests() {
	// Create a temp file with known content.
	tmpDir, err := os.MkdirTemp("", "dpc-test-*")
	if err != nil {
		printFail("Could not create temp dir: " + err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "testdata.txt")
	payload := []byte("Deepcrypt cipher-suite test — " + time.Now().Format(time.RFC3339Nano))
	if err := os.WriteFile(testFile, payload, 0644); err != nil {
		printFail("Could not write test file: " + err.Error())
		return
	}

	width := 52
	bar := strings.Repeat("─", width)

	fmt.Println(styleDim.Render("  ┌" + bar + "┐"))
	fmt.Println(styleDim.Render("  │") + styleInfo.Render(center("DEEPCRYPT CIPHER-SUITE VERIFICATION", width)) + styleDim.Render("│"))
	fmt.Println(styleDim.Render("  └" + bar + "┘"))
	fmt.Println()

	pass, fail := 0, 0
	start := time.Now()

	for _, tc := range cipherTests {
		// Recreate the test file — a previous test removes it before decrypting.
		if err := os.WriteFile(testFile, payload, 0644); err != nil {
			printFail("Could not recreate test file: " + err.Error())
			return
		}
		ok, dur, detail := runOneTest(tc, testFile, payload)

		var badge string
		switch tc.tier {
		case "red":
			badge = tierRed.Render("●")
		case "yellow":
			badge = tierYellow.Render("●")
		default:
			badge = tierGreen.Render("●")
		}

		label := fmt.Sprintf("  %s %s  %s", badge, tc.icon, tc.name)
		timing := styleDim.Render(fmt.Sprintf("(%dms)", dur.Milliseconds()))

		if ok {
			fmt.Printf("%s  %s  %s\n", label, styleOK.Render("PASS"), timing)
			pass++
		} else {
			fmt.Printf("%s  %s  %s\n", label, styleErr.Render("FAIL"), styleDim.Render(detail))
			fail++
		}
	}

	fmt.Println()
	total := time.Since(start)
	summary := fmt.Sprintf("  %d/%d passed  ·  %dms total", pass, pass+fail, total.Milliseconds())
	if fail == 0 {
		fmt.Println(styleOK.Render(summary))
	} else {
		fmt.Println(styleErr.Render(summary))
	}
	fmt.Println()
}

func runOneTest(tc testCase, testFile string, original []byte) (ok bool, dur time.Duration, detail string) {
	t0 := time.Now()

	// Encrypt (no password; test always runs in shareable mode).
	result, err := encryptTarget(testFile, tc.algo, false, "")
	if err != nil {
		return false, time.Since(t0), "encrypt: " + err.Error()
	}
	defer func() {
		os.Remove(result.DCPPath)
		os.Remove(result.KeyPath)
	}()

	// Remove the original so decrypt can restore it without a name collision.
	// (Mirroring real usage: encrypt → delete original → later decrypt to restore.)
	os.Remove(testFile)

	// Decrypt.
	decResult, err := decryptTarget(result.DCPPath, result.KeyPath, "")
	if err != nil {
		return false, time.Since(t0), "decrypt: " + err.Error()
	}
	defer os.Remove(decResult.OutPath)

	// Verify content.
	got, err := os.ReadFile(decResult.OutPath)
	if err != nil {
		return false, time.Since(t0), "read output: " + err.Error()
	}
	if !bytes.Equal(got, original) {
		return false, time.Since(t0), "content mismatch"
	}
	return true, time.Since(t0), ""
}

func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := (width - len(s)) / 2
	return strings.Repeat(" ", pad) + s + strings.Repeat(" ", width-len(s)-pad)
}
