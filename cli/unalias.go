package main

type UnaliasCommand struct {
	Alias string `arg:""`
}

func (u UnaliasCommand) Run(ctx AppContext) error {
	ctx.Config.Unalias(u.Alias)
	return nil
}
