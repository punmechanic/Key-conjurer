package main

import (
	"github.com/spf13/cobra"
)

var (
	FlagOIDCDomain = "oidc-domain"
	FlagClientID   = "client-id"
	FlagConfigPath = "config"
	FlagQuiet      = "quiet"
	FlagTimeout    = "timeout"
	cloudAws       = "aws"
	cloudTencent   = "tencent"
)

func init() {
	rootCmd.PersistentFlags().String(FlagOIDCDomain, OIDCDomain, "The domain name of your OIDC server")
	rootCmd.PersistentFlags().String(FlagClientID, ClientID, "The OAuth2 Client ID for the application registered with your OIDC server")
	rootCmd.PersistentFlags().Int(FlagTimeout, 120, "the amount of time in seconds to wait for keyconjurer to respond")
	rootCmd.PersistentFlags().String(FlagConfigPath, "~/.keyconjurerrc", "path to .keyconjurerrc file")
	rootCmd.PersistentFlags().Bool(FlagQuiet, false, "tells the CLI to be quiet; stdout will not contain human-readable informational messages")
	rootCmd.AddCommand(accountsCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(&switchCmd)
	rootCmd.AddCommand(&aliasCmd)
	rootCmd.AddCommand(&unaliasCmd)
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keyconjurer",
	Short: "Retrieve temporary cloud credentials.",
	FParseErrWhitelist: cobra.FParseErrWhitelist{
		UnknownFlags: true,
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}
