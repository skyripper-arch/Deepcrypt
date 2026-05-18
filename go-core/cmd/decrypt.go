package cmd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	var keyPath  string
	var password string

	c := &cobra.Command{
		Use:   "decrypt <file.dpec>",
		Short: "Decrypt a .dpec file using the paired .key file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no password flag was given, check whether the key file needs one
			// and prompt interactively when attached to a terminal.
			if password == "" && peekNeedsPassword(keyPath) {
				if term.IsTerminal(int(os.Stdin.Fd())) {
					fmt.Print("  Password: ")
					raw, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return fmt.Errorf("password prompt: %w", err)
					}
					password = string(raw)
				}
			}

			fmt.Println(styleInfo.Render("[dpc] Decrypting..."))
			result, err := decryptTarget(args[0], keyPath, password)
			if errors.Is(err, ErrPasswordRequired) {
				return fmt.Errorf("this file requires a password — use --password or run interactively")
			}
			if err != nil {
				return err
			}
			fmt.Println(styleOK.Render("  ✓ Decryption complete."))
			if result.WasDir {
				fmt.Printf("    Extracted to : %s\n", result.OutPath)
			} else {
				fmt.Printf("    Output : %s (%d bytes)\n", result.OutPath, result.PlaintextSz)
			}
			return nil
		},
	}

	c.Flags().StringVar(&keyPath, "key", "", "Path to .key file (required)")
	c.Flags().StringVar(&password, "password", "", "Decryption password (if the file was encrypted with one)")
	_ = c.MarkFlagRequired("key")
	return c
}
