package cmd

import (
	"fmt"
	"os"

	"deepcrypt/internal/format"
	"deepcrypt/internal/settings"

	"golang.org/x/term"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var algo     string
	var b64      bool
	var password string

	c := &cobra.Command{
		Use:   "encrypt <path>",
		Short: "Encrypt a file or folder → <name>.dcp + <name>.key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no --password flag was given, check settings and prompt on a terminal.
			if password == "" {
				s := settings.Load()
				if s.UsePassword && term.IsTerminal(int(os.Stdin.Fd())) {
					fmt.Print("  Encryption password: ")
					raw, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return fmt.Errorf("password prompt: %w", err)
					}
					fmt.Print("  Confirm password:    ")
					confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return fmt.Errorf("password confirm: %w", err)
					}
					if string(raw) != string(confirm) {
						return fmt.Errorf("passwords do not match")
					}
					password = string(raw)
				}
			}

			fmt.Println(styleInfo.Render("[dpc] Collecting entropy + deriving key..."))
			result, err := encryptTarget(args[0], algo, b64, password)
			if err != nil {
				return err
			}
			fmt.Println(styleOK.Render("  ✓ Encryption complete."))
			fmt.Printf("    Algorithm  : %s\n", format.AlgoName(result.AlgoID))
			fmt.Printf("    Output     : %s (%d bytes)\n", result.DCPPath, result.FileSize)
			fmt.Printf("    Key file   : %s\n", result.KeyPath)
			if result.WasDir {
				fmt.Println("    Type       : directory archive")
			}
			return nil
		},
	}

	c.Flags().StringVar(&algo, "algo", "aes", "Cipher suite: aes|chacha|rsa|ecc|pqc|twofish|blowfish|3des|des|b64|luac")
	c.Flags().BoolVar(&b64, "b64", false, "Base64-encode the .dcp payload")
	c.Flags().StringVar(&password, "password", "", "Encryption password (stored in key derivation, not on disk)")
	return c
}
