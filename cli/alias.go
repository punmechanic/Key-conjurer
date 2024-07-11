package main

type AliasCommand struct {
	Account string `arg:"0"`
	Alias   string `arg:"1"`
}

func (a AliasCommand) Run(ctx AppContext) error {
	ctx.Config.Alias(a.Account, a.Alias)
	return nil
}
