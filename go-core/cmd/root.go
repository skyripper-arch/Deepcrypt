package cmd

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var bannerStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#00FF87")).
	Bold(true)

var bannerDim = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#626262"))

const asciiLogo = `
  ██████╗ ██████╗  ██████╗
  ██╔══██╗██╔══██╗██╔════╝
  ██║  ██║██████╔╝██║
  ██║  ██║██╔═══╝ ██║
  ██████╔╝██║     ╚██████╗  v1.0.0
  ╚═════╝ ╚═╝      ╚═════╝`

func printBanner() {
	fmt.Println(bannerStyle.Render(asciiLogo))
	fmt.Println()
	fmt.Println(bannerDim.Render("  ╔══════════════════════════════════════════════════╗"))
	fmt.Println(bannerDim.Render("  ║") + styleInfo.Render("  POST-QUANTUM FILE ENCRYPTION ENGINE             ") + bannerDim.Render("║"))
	fmt.Println(bannerDim.Render("  ║") + styleDim.Render("  HWID-Bound  ·  Argon2id KDF  ·  .dcp format    ") + bannerDim.Render("║"))
	fmt.Println(bannerDim.Render("  ╚══════════════════════════════════════════════════╝"))
	fmt.Println()
}

var rootCmd = &cobra.Command{
	Use:   "dpc",
	Short: "Post-quantum file encryption engine",
	Long:  "Deepcrypt — HWID-bound, multi-algorithm, post-quantum capable file encryption.",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		// Launch interactive TUI only when connected to a real terminal.
		if term.IsTerminal(int(os.Stdin.Fd())) {
			runInteractive()
		} else {
			fmt.Fprintln(os.Stderr, "  Usage: dpc encrypt <path> --algo <suite>")
			fmt.Fprintln(os.Stderr, "         dpc decrypt <file.dcp> --key <file.key>")
			fmt.Fprintln(os.Stderr, "         dpc test")
			fmt.Fprintln(os.Stderr, "         dpc --help")
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newEncryptCmd())
	rootCmd.AddCommand(newDecryptCmd())
	rootCmd.AddCommand(newTestCmd())
}
