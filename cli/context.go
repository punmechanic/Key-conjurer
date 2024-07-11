package main

import (
	"io"
	"time"
)

// TODO: I suspect that having this struct implement context is a bad idea;
// the timeout/deadline function likely will not work without us essentially
// replicating context.Context.

type AppContext struct {
	Config       *Config
	OIDCDomain   string
	OIDCClientID string

	Stdout  io.Writer
	Timeout time.Time
}

func (c AppContext) Deadline() (time.Time, bool) {
	return c.Timeout, !c.Timeout.IsZero()
}

func (AppContext) Done() <-chan struct{} {
	return nil
}

func (AppContext) Err() error {
	return nil
}

func (AppContext) Value(key any) any {
	return nil
}
