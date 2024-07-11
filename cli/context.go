package main

import (
	"io"
	"time"
)

type AppContext struct {
	Config       *Config
	OIDCDomain   string
	OIDCClientID string

	Stdout io.Writer
}

func (AppContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
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
