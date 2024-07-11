package main

import (
	"context"
	"io"
	"time"

	"github.com/spf13/cobra"
)

type configInfo struct {
	Path   string
	Config *Config
}

type ctxKeyConfig struct{}

func ConfigFromCommand(cmd *cobra.Command) *Config {
	return cmd.Context().Value(ctxKeyConfig{}).(*configInfo).Config
}

func ConfigPathFromCommand(cmd *cobra.Command) string {
	return cmd.Context().Value(ctxKeyConfig{}).(*configInfo).Path
}

func ConfigContext(ctx context.Context, config *Config, path string) context.Context {
	return context.WithValue(ctx, ctxKeyConfig{}, &configInfo{Path: path, Config: config})
}

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
