package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Ensure AppContext implements context.Context
var _ context.Context = AppContext{}

func Test_Context_Deadline(t *testing.T) {
	expected := time.Now().Add(5 * time.Millisecond)
	ctx := AppContext{
		Timeout: expected,
	}

	dl, ok := ctx.Deadline()
	assert.Equal(t, expected, dl)
	assert.True(t, ok)

	// Ensure that it also works with the zero value
	var zv time.Time
	ctx = AppContext{
		Timeout: zv,
	}

	dl, ok = ctx.Deadline()
	assert.Equal(t, zv, dl)
	assert.False(t, ok)
}
