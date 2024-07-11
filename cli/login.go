package main

import (
	"context"
	"fmt"
	"os"

	"log/slog"

	"github.com/pkg/browser"
)

var (
	LoginOutputBrowser  = "browser"
	LoginOutputURL      = "url"
	LoginOutputFriendly = "friendly"
)

type LoginCommand struct {
	OIDCDomain string `hidden:""`
	ClientID   string `hidden:""`
	Output     string `enum:"browser,url,friendly" default:"browser"`
}

func (c LoginCommand) Help() string {
	return "You will be required to open the URL printed to the console."
}

func (c LoginCommand) Run(ctx AppContext) error {
	oauthCfg, err := DiscoverOAuth2Config(ctx, c.OIDCDomain, c.ClientID)
	if err != nil {
		return err
	}

	var fn func(string) error
	switch c.Output {
	case LoginOutputFriendly:
		fn = friendlyPrintURLToConsole
	case LoginOutputBrowser:
		fn = openBrowserToURL
	case LoginOutputURL:
		fn = printURLToConsole
	}

	handler := RedirectionFlowHandler{
		Config:       oauthCfg,
		Listen:       ListenAnyPort("127.0.0.1", CallbackPorts),
		OnDisplayURL: fn,
	}

	state := GenerateState()
	challenge := GeneratePkceChallenge()
	token, err := handler.HandlePendingSession(context.TODO(), challenge, state)
	if err != nil {
		return err
	}

	return ctx.Config.SaveOAuthToken(token)
}

func printURLToConsole(url string) error {
	fmt.Fprintln(os.Stdout, url)
	return nil
}

func friendlyPrintURLToConsole(url string) error {
	fmt.Printf("Visit the following link in your terminal: %s\n", url)
	return nil
}

func openBrowserToURL(url string) error {
	slog.Debug("trying to open browser window", slog.String("url", url))
	return browser.OpenURL(url)
}
