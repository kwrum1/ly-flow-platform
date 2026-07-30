//go:build !pfring

package main

import "fmt"

func pfringAdapterCompiled() bool { return false }

func (a *Agent) runPFRingCapture() error {
	return fmt.Errorf("PF_RING adapter is not compiled into this agent")
}
