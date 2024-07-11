package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/riotgames/key-conjurer/internal/api"
	"golang.org/x/oauth2"
)

var ErrSessionExpired = errors.New("session expired")

type AccountsCommand struct {
	NoRefresh     bool   `help:"Indicate that the account list should not be refreshed when executing this command. This is useful if you're not able to reach the account server."`
	ServerAddress string `name:"address" help:"The address of the account server" hidden:"" optional:""`
}

func (a AccountsCommand) Run(ctx AppContext) error {
	if a.ServerAddress == "" {
		a.ServerAddress = ServerAddress
	}
	config := ctx.Config
	if a.NoRefresh {
		config.DumpAccounts(ctx.Stdout, true)
		return nil
	}

	serverAddrURI, err := url.Parse(a.ServerAddress)
	if err != nil {
		return genericError{
			ExitCode: ExitCodeValueError,
			Message:  fmt.Sprintf("--address had an invalid value: %s\n", err),
		}
	}

	if HasTokenExpired(config.Tokens) {
		return ErrTokensExpiredOrAbsent
	}

	tok := oauth2.Token{
		AccessToken:  config.Tokens.AccessToken,
		RefreshToken: config.Tokens.RefreshToken,
		Expiry:       config.Tokens.Expiry,
		TokenType:    config.Tokens.TokenType,
	}

	accounts, err := refreshAccounts(ctx, serverAddrURI, &tok)
	if err != nil {
		return fmt.Errorf("error refreshing accounts: %w", err)
	}

	config.UpdateAccounts(accounts)
	config.DumpAccounts(ctx.Stdout, true)
	return nil
}

func refreshAccounts(ctx context.Context, serverAddr *url.URL, tok *oauth2.Token) ([]Account, error) {
	uri := serverAddr.ResolveReference(&url.URL{Path: "/v2/applications"})
	httpClient := NewHTTPClient()
	req, _ := http.NewRequestWithContext(ctx, "POST", uri.String(), nil)
	tok.SetAuthHeader(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %s", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read body: %s", err)
	}

	var jsonError api.JSONError
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 0 {
		if err := json.Unmarshal(body, &jsonError); err != nil {
			return nil, errors.New(jsonError.Message)

		}
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var apps []api.Application
	if err := json.Unmarshal(body, &apps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal applications: %w", err)
	}

	entries := make([]Account, len(apps))
	for idx, app := range apps {
		entries[idx] = Account{
			ID:    app.ID,
			Name:  app.Name,
			Alias: generateDefaultAlias(app.Name),
		}
	}

	return entries, nil
}
