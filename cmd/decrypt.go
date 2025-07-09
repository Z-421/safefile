package cmd

import (
	"fmt"
	"os"

	"github.com/Z-421/safefile/safefile"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file",
	Long:  `Decrypt a previously encrypted file with the correct password.`,
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

		err := safefile.DecryptAndSaveFile(input, output, []byte(password))
		if err != nil {
			fmt.Println("Error decrypting file:", err)
			return
		}
		fmt.Println("File decrypted successfully!")
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("input", "i", "", "Input file path")
	decryptCmd.Flags().StringP("output", "o", "", "Output file path")
	decryptCmd.Flags().StringP("password", "p", "", "Password for decryption")

	decryptCmd.MarkFlagRequired("input")
	decryptCmd.MarkFlagRequired("output")
}
