package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"deepcrypt/internal/format"
	"deepcrypt/internal/settings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ── Shared styles (used by encrypt.go / decrypt.go / test.go too) ─────────────

var (
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).Bold(true)
	styleInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("#87AFFF"))
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("#626262"))
	styleBold   = lipgloss.NewStyle().Bold(true)

	// Tier badge colours used in the algorithm selector.
	tierRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).Bold(true)
	tierYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	tierGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
)

// algoOption builds a huh option label with a coloured security-tier badge.
//   tier: "red" | "yellow" | "green"
func algoOption(tier, label, value string) huh.Option[string] {
	var badge string
	switch tier {
	case "red":
		badge = tierRed.Render("●")
	case "yellow":
		badge = tierYellow.Render("●")
	default:
		badge = tierGreen.Render("●")
	}
	return huh.NewOption[string](badge+"  "+label, value)
}

func printOK(msg string)   { fmt.Println("  " + styleOK.Render("✓") + "  " + msg) }
func printFail(msg string) { fmt.Println("  " + styleErr.Render("✗") + "  " + styleErr.Render(msg)) }
func printInfo(msg string) { fmt.Println("  " + styleInfo.Render("›") + "  " + msg) }

// theme returns the shared huh theme used by all interactive forms.
// ThemeDracula + fixed width eliminates the viewport-resize glitch on Windows.
func theme() *huh.Theme { return huh.ThemeDracula() }

// newForm wraps fields in a form with consistent theme and width so that the
// select viewport never resizes during key-hold, which caused the glitch.
func newForm(fields ...huh.Field) *huh.Form {
	return huh.NewForm(huh.NewGroup(fields...)).
		WithTheme(theme()).
		WithWidth(64).
		WithShowHelp(true)
}

// spin runs fn in a goroutine and shows a braille-frame spinner until done.
func spin(title string, fn func() error) error {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	i := 0
	for {
		select {
		case err := <-done:
			fmt.Printf("\r\033[K")
			return err
		default:
			fmt.Printf("\r  %s  %s",
				styleYellow.Render(frames[i%len(frames)]),
				styleInfo.Render(title),
			)
			_ = os.Stdout.Sync()
			i++
			time.Sleep(80 * time.Millisecond)
		}
	}
}

// ── Main menu ─────────────────────────────────────────────────────────────────

func runInteractive() {
	var action string

	err := newForm(
		huh.NewSelect[string]().
			Title("  What would you like to do?").
			Height(7).
			Options(
				huh.NewOption("🔒  Encrypt  — protect a file or folder", "encrypt"),
				huh.NewOption("🔓  Decrypt  — restore from a .dcp file", "decrypt"),
				huh.NewOption("🧪  Test     — verify all cipher suites", "test"),
				huh.NewOption("⚙   Settings — machine lock & password", "settings"),
				huh.NewOption("✕   Exit", "exit"),
			).
			Value(&action),
	).Run()

	if err != nil || action == "exit" {
		fmt.Println(styleDim.Render("\n  Goodbye.\n"))
		return
	}

	fmt.Println()
	switch action {
	case "encrypt":
		interactiveEncrypt()
	case "decrypt":
		interactiveDecrypt()
	case "test":
		interactiveTest()
	case "settings":
		interactiveSettings()
	}
}

// ── Encrypt flow ──────────────────────────────────────────────────────────────

func interactiveEncrypt() {
	// Step 1 — file / folder path
	var filePath string
	err := newForm(
		huh.NewInput().
			Title("  File or folder to encrypt").
			Description("Drag & drop into the terminal, or type the full path").
			Placeholder(`C:\Users\you\secret.pdf`).
			Value(&filePath),
	).Run()
	if aborted(err) {
		return
	}
	filePath = strings.Trim(filePath, `"' `)

	if _, err := os.Stat(filePath); err != nil {
		printFail("Path not found: " + filePath)
		return
	}

	// Step 2 — algorithm
	// Legend: ● Red = strongest  ● Yellow = medium  ● Green = weakest
	var algoName string
	err = newForm(
		huh.NewSelect[string]().
			Title("  Encryption algorithm  ["+tierRed.Render("● strongest")+"  "+tierYellow.Render("● medium")+"  "+tierGreen.Render("● weakest")+"]").
			Height(13).
			Options(
				algoOption("red", "ML-KEM-768 (PQC)      post-quantum · Kyber768 · strongest", "pqc"),
				algoOption("red", "AES-256-GCM           fast · authenticated · recommended", "aes"),
				algoOption("red", "XChaCha20-Poly1305    fast stream cipher", "chacha"),
				algoOption("red", "RSA-4096-OAEP         asymmetric hybrid  (slow keygen)", "rsa"),
				algoOption("red", "ECC / Curve25519      elliptic-curve ECIES", "ecc"),
				algoOption("red", "Twofish-256-CBC       strong symmetric block cipher", "twofish"),
				algoOption("yellow", "Blowfish-448-CBC    legacy · medium strength", "blowfish"),
				algoOption("yellow", "3DES (Triple-DES)   legacy · medium · slow", "3des"),
				algoOption("green", "DES-CBC              legacy · weak · not recommended", "des"),
				algoOption("green", "Base64               encoding only · NO encryption", "b64"),
				algoOption("green", "Lua-XOR              obfuscation only · minimal security", "luac"),
			).
			Value(&algoName),
	).Run()
	if aborted(err) {
		return
	}

	// Step 3 — password (if enabled in settings)
	password := ""
	s := settings.Load()
	if s.UsePassword {
		var pw, confirm string
		err = newForm(
			huh.NewInput().
				Title("  Set decryption password").
				Description("This password will be required to decrypt this file.").
				EchoMode(huh.EchoModePassword).
				Value(&pw),
			huh.NewInput().
				Title("  Confirm password").
				EchoMode(huh.EchoModePassword).
				Value(&confirm),
		).Run()
		if aborted(err) {
			return
		}
		if pw != confirm {
			printFail("Passwords do not match.")
			return
		}
		if pw == "" {
			printFail("Password cannot be empty when password protection is enabled.")
			return
		}
		password = pw
	}

	// Step 4 — encrypt with spinner
	var result *EncryptResult
	spinErr := spin("Collecting entropy · Deriving key · Encrypting…", func() error {
		var e error
		result, e = encryptTarget(filePath, algoName, false, password)
		return e
	})

	fmt.Println()
	if spinErr != nil {
		printFail("Encryption failed: " + spinErr.Error())
		return
	}
	printOK(styleOK.Render("Encryption complete!"))
	printInfo("Algorithm  " + format.AlgoName(result.AlgoID))
	printInfo(fmt.Sprintf("Output     %s  %s",
		result.DCPPath, styleDim.Render(fmt.Sprintf("(%d bytes)", result.FileSize))))
	printInfo("Key file   " + result.KeyPath)
	if result.WasDir {
		printInfo("Type       " + styleBold.Render("directory archive"))
	}
	if s.MachineLock.Enabled && s.MachineLock.ActiveCount() > 0 {
		printInfo("Lock       " + styleYellow.Render("machine-bound") +
			fmt.Sprintf("  (%d factors)", s.MachineLock.ActiveCount()))
	}
	if password != "" {
		printInfo("Password   " + styleYellow.Render("protected"))
	}
	fmt.Println()
}

// ── Decrypt flow ──────────────────────────────────────────────────────────────

func interactiveDecrypt() {
	// Collect both paths in one form.
	var dcpPath, keyPath string
	err := newForm(
		huh.NewInput().
			Title("  Path to the .dcp file").
			Description("Drag & drop the encrypted file into the terminal").
			Placeholder(`C:\Users\you\secret.dcp`).
			Value(&dcpPath),
		huh.NewInput().
			Title("  Path to the .key file").
			Description("The key file produced alongside the .dcp").
			Placeholder(`C:\Users\you\secret.key`).
			Value(&keyPath),
	).Run()
	if aborted(err) {
		return
	}
	dcpPath = strings.Trim(dcpPath, `"' `)
	keyPath = strings.Trim(keyPath, `"' `)

	// Peek at the key file to see if a password is required before spinning.
	password := ""
	if peekNeedsPassword(keyPath) {
		var pw string
		err = newForm(
			huh.NewInput().
				Title("  Decryption password").
				Description("This file was encrypted with a password.").
				EchoMode(huh.EchoModePassword).
				Value(&pw),
		).Run()
		if aborted(err) {
			return
		}
		password = pw
	}

	var result *DecryptResult
	spinErr := spin("Re-deriving key · Verifying machine · Decrypting…", func() error {
		var e error
		result, e = decryptTarget(dcpPath, keyPath, password)
		return e
	})

	// Fallback: if key file couldn't be peeked but password is still needed.
	if errors.Is(spinErr, ErrPasswordRequired) {
		var pw string
		err = newForm(
			huh.NewInput().
				Title("  Decryption password").
				EchoMode(huh.EchoModePassword).
				Value(&pw),
		).Run()
		if aborted(err) {
			return
		}
		password = pw
		spinErr = spin("Re-deriving key · Decrypting…", func() error {
			var e error
			result, e = decryptTarget(dcpPath, keyPath, password)
			return e
		})
	}

	fmt.Println()
	if spinErr != nil {
		printFail("Decryption failed: " + spinErr.Error())
		return
	}
	printOK(styleOK.Render("Decryption complete!"))
	if result.WasDir {
		printInfo("Extracted to  " + result.OutPath)
	} else {
		printInfo(fmt.Sprintf("Output  %s  %s",
			result.OutPath, styleDim.Render(fmt.Sprintf("(%d bytes)", result.PlaintextSz))))
	}
	fmt.Println()
}

// ── Test flow ─────────────────────────────────────────────────────────────────

func interactiveTest() {
	fmt.Println(styleBold.Render("  Running cipher suite tests…\n"))
	runAllTests()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func aborted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, huh.ErrUserAborted) {
		fmt.Println(styleDim.Render("  Cancelled."))
	} else {
		printFail(err.Error())
	}
	return true
}
