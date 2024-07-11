package main

import (
	"fmt"
	"os"
)

type RolesCommand struct {
	Account string `arg:"" required:""`
}

func (RolesCommand) Help() string {
	return "Returns the roles that you have access to in the given account."
}

func (r RolesCommand) Run(ctx AppContext) error {
	if ctx.Stdout == nil {
		ctx.Stdout = os.Stdout
	}

	if HasTokenExpired(ctx.Config.Tokens) {
		return ErrTokensExpiredOrAbsent
	}

	account, ok := ctx.Config.FindAccount(r.Account)
	if ok {
		r.Account = account.ID
	}

	samlResponse, _, err := DiscoverConfigAndExchangeTokenForAssertion(ctx, NewHTTPClient(), ctx.Config.Tokens, ctx.OIDCDomain, ctx.OIDCClientID, r.Account)
	if err != nil {
		return err
	}

	for _, name := range ListSAMLRoles(samlResponse) {
		fmt.Fprintln(ctx.Stdout, name)
	}

	return nil
}
