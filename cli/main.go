package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"log/slog"

	"github.com/alecthomas/kong"
	"github.com/spf13/cobra"
)

const (
	// WSAEACCES is the Windows error code for attempting to access a socket that you don't have permission to access.
	//
	// This commonly occurs if the socket is in use or was not closed correctly, and can be resolved by restarting the hns service.
	WSAEACCES = 10013
)

// IsWindowsPortAccessError determines if the given error is the error WSAEACCES.
func IsWindowsPortAccessError(err error) bool {
	var syscallErr *syscall.Errno
	return errors.As(err, &syscallErr) && *syscallErr == WSAEACCES
}

func init() {
	var opts slog.HandlerOptions
	if os.Getenv("DEBUG") == "1" {
		opts.Level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stdout, &opts)
	slog.SetDefault(slog.New(handler))
}

type CLI struct {
	Login        LoginCommand `cmd:"login" help:"Log in to KeyConjurer using a web browser."`
	Get          GetCommand   `cmd:"get" help:"Retrieves temporary cloud API credentials."`
	Alias        struct{}     `cmd:"alias"`
	Unalias      struct{}     `cmd:"unalias"`
	ListAccounts struct{}     `cmd:"accounts" name:"accounts"`
	ListRoles    RolesCommand `cmd:"roles" name:"roles"`

	OIDCDomain   string `name:"oidc_domain" hidden:"" help:"The domain of the OIDC IdP to use as an authorization server"`
	OIDCClientID string `name:"client_id" hidden:"" help:"The client ID of the OIDC application to identify as"`
	ConfigPath   string `name:"config" help:"The path to the configuration file" default:"~/.config/keyconjurer/config.json"`
	Version      bool   `help:"Emit version information"`
	Timeout      int    `help:"Amount of time in seconds to wait for KeyConjurer to respond" default:"120"`
}

type AppContext struct {
	Config       *Config
	OIDCDomain   string
	OIDCClientID string
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli, kong.Name("keyconjurer"), kong.Description(`KeyConjurer retrieves temporary credentials from Okta with the assistance of an optional API.

To get started run the following commands:
	keyconjurer login
	keyconjurer accounts
	keyconjurer get <accountName>
	`))

	configPath := kong.ExpandPath(cli.ConfigPath)
	config, err := LoadConfiguration(configPath)
	if err != nil {
		// Could not load configuration file
		fmt.Fprintf(os.Stderr, "could not load configuration file %s: %s\n", configPath, err)
		os.Exit(1)
	}

	if cli.Version {
		version := fmt.Sprintf("keyconjurer-%s-%s %s (%s)", runtime.GOOS, runtime.GOARCH, Version, BuildTimestamp)
		fmt.Fprintln(os.Stdout, version)
		return
	}

	appCtx := AppContext{
		Config:       &config,
		OIDCDomain:   cli.OIDCDomain,
		OIDCClientID: cli.OIDCClientID,
	}

	// Set the defaults that are injected by the build process if the user didn't provide any.
	if appCtx.OIDCClientID == "" {
		appCtx.OIDCClientID = ClientID
	}

	if appCtx.OIDCDomain == "" {
		appCtx.OIDCDomain = OIDCDomain
	}

	// TODO:
	// timeout, _ := cmd.Flags().GetInt(FlagTimeout)
	// nextCtx, _ := context.WithTimeout(cmd.Context(), time.Duration(timeout)*time.Second)
	// cmd.SetContext(ConfigContext(nextCtx, &config, configPath))

	err = ctx.Run(&appCtx)

	if IsWindowsPortAccessError(err) {
		fmt.Fprintf(os.Stderr, "Encountered an issue when opening the port for KeyConjurer: %s\n", err)
		fmt.Fprintln(os.Stderr, "Consider running `net stop hns` and then `net start hns`")
		os.Exit(ExitCodeConnectivityError)
	}

	var codeErr codeError
	if errors.As(err, &codeErr) {
		cobra.CheckErr(codeErr)
		os.Exit(int(codeErr.Code()))
	} else if err != nil {
		// Probably a cobra error.
		cobra.CheckErr(err)
		os.Exit(ExitCodeUnknownError)
	}

	err = SaveConfiguration(configPath, config)
	if err != nil {
		// Could not save configuration for some reason
		fmt.Fprintf(os.Stderr, "Could not save configuration: %s\n", err)
		os.Exit(1)
	}
}
