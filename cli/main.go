package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"log/slog"

	"github.com/alecthomas/kong"
)

const (
	// WSAEACCES is the Windows error code for attempting to access a socket that you don't have permission to access.
	//
	// This commonly occurs if the socket is in use or was not closed correctly, and can be resolved by restarting the hns service.
	WSAEACCES    = 10013
	cloudAws     = "aws"
	cloudTencent = "tencent"
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
	Login        LoginCommand    `cmd:"login" help:"Log in to KeyConjurer using a web browser."`
	Get          GetCommand      `cmd:"get" help:"Retrieves temporary cloud API credentials."`
	Alias        AliasCommand    `cmd:"alias" help:"Give an account a nickname."`
	Unalias      UnaliasCommand  `cmd:"unalias" help:"Remove alias from account."`
	ListAccounts AccountsCommand `cmd:"accounts" name:"accounts" help:"List accounts you have access to."`
	ListRoles    RolesCommand    `cmd:"roles" name:"roles" help:"List roles for an account."`
	Set          struct {
		TTL           TimeToLiveCommand    `cmd:"ttl" help:"Sets ttl value in number of hours."`
		TimeRemaining TimeRemainingCommand `cmd:"time-remaining" help:"Sets time remaining value in number of minutes."`
	} `cmd:"set" help:"Configure KeyConjurer."`

	OIDCDomain   string `name:"oidc_domain" hidden:"" help:"The domain of the OIDC IdP to use as an authorization server"`
	OIDCClientID string `name:"client_id" hidden:"" help:"The client ID of the OIDC application to identify as"`
	ConfigPath   string `name:"config" help:"The path to the configuration file" default:"~/.config/keyconjurer/config.json"`
	Version      bool   `help:"Emit version information"`
	Timeout      int    `help:"Amount of time in seconds to wait for KeyConjurer to respond" default:"120"`
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
		Timeout:      time.Now().Add(time.Duration(cli.Timeout) * time.Second),
	}

	// Set the defaults that are injected by the build process if the user didn't provide any.
	if appCtx.OIDCClientID == "" {
		appCtx.OIDCClientID = ClientID
	}

	if appCtx.OIDCDomain == "" {
		appCtx.OIDCDomain = OIDCDomain
	}

	err = ctx.Run(appCtx)

	if IsWindowsPortAccessError(err) {
		fmt.Fprintf(os.Stderr, "Encountered an issue when opening the port for KeyConjurer: %s\n", err)
		fmt.Fprintln(os.Stderr, "Consider running `net stop hns` and then `net start hns`")
		os.Exit(ExitCodeConnectivityError)
	}

	var codeErr codeError
	if errors.As(err, &codeErr) {
		checkErr(codeErr)
		os.Exit(int(codeErr.Code()))
	} else if err != nil {
		// Probably a cobra error.
		checkErr(err)
		os.Exit(ExitCodeUnknownError)
	}

	err = SaveConfiguration(configPath, config)
	if err != nil {
		// Could not save configuration for some reason
		fmt.Fprintf(os.Stderr, "Could not save configuration: %s\n", err)
		os.Exit(1)
	}
}

// checkErr prints the msg with the prefix 'Error:' and exits with error code 1. If the msg is nil, it does nothing.
//
// Copied from Cobra.
func checkErr(msg interface{}) {
	if msg != nil {
		fmt.Fprintln(os.Stderr, "Error:", msg)
		os.Exit(1)
	}
}
