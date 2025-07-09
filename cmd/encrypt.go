package cmd

import (
	"fmt"
	"os"

	"github.com/Z-421/safefile/safefile"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file",
	Long:  `Encrypt a file with a password and save the encrypted output.`,
	Run: func(cmd *cobra.Command, args []string) {
		input, _ := cmd.Flags().GetString("input")
		output, _ := cmd.Flags().GetString("output")
		password, _ := cmd.Flags().GetString("password")

		if password == "" {
			fmt.Print("Password: ")
			bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Println("Error reading password:", err)
				return
			}
			password = string(bytePassword)
		}

		err := safefile.EncryptAndSaveFile(input, output, []byte(password))
		if err != nil {
			fmt.Println("Error encrypting file:", err)
			return
		}
		fmt.Println("File encrypted successfully!")
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringP("input", "i", "", "Input file path")
	encryptCmd.Flags().StringP("output", "o", "", "Output file path")
	encryptCmd.Flags().StringP("password", "p", "", "Password for encryption")

	encryptCmd.MarkFlagRequired("input")
	encryptCmd.MarkFlagRequired("output")
}
