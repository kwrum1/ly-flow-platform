//go:build !linux

package main

import (
	"context"
	"errors"
)

func listenRaw(context.Context, uint16, *Collector) error {
	return errors.New("raw NetFlow listener is only supported on Linux")
}
