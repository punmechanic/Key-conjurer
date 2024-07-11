package main

import "context"

// Ensure AppContext implements context.Context
var _ context.Context = AppContext{}
