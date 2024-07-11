package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

type RolesCommand struct {
	Account string `arg:"" required:""`

	Stdout io.Writer
}

func (RolesCommand) Help() string {
	return "Returns the roles that you have access to in the given account."
}

func (r RolesCommand) Roles(appCtx *AppContext) error {
	if r.Stdout == nil {
		r.Stdout = os.Stdout
	}

	if HasTokenExpired(appCtx.Config.Tokens) {
		return ErrTokensExpiredOrAbsent
	}

	account, ok := appCtx.Config.FindAccount(r.Account)
	if ok {
		r.Account = account.ID
	}

	ctx := context.Background()
	samlResponse, _, err := DiscoverConfigAndExchangeTokenForAssertion(ctx, NewHTTPClient(), appCtx.Config.Tokens, appCtx.OIDCDomain, appCtx.OIDCClientID, r.Account)
	if err != nil {
		return err
	}

	for _, name := range ListSAMLRoles(samlResponse) {
		fmt.Fprintln(r.Stdout, name)
	}

	return nil
}
