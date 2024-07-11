package main

type TimeToLiveCommand struct {
	Hours uint `arg:""`
}

func (t TimeToLiveCommand) Run(ctx AppContext) error {
	// ttl, err := strconv.ParseUint(args[0], 10, 32)
	// if err != nil {
	// 	return fmt.Errorf("unable to parse value %s", args[0])
	// }
	ctx.Config.TTL = t.Hours
	return nil
}

type TimeRemainingCommand struct {
	Minutes uint `arg:""`
}

func (t TimeRemainingCommand) Run(ctx AppContext) error {
	// ttl, err := strconv.ParseUint(args[0], 10, 32)
	// if err != nil {
	// 	return fmt.Errorf("unable to parse value %s", args[0])
	// }
	ctx.Config.TimeRemaining = t.Minutes
	return nil
}
