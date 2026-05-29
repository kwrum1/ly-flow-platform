//go:build !linux

package main

import "fmt"

func (a *Agent) runAFPacketCapture() error {
	return fmt.Errorf("af_packet capture is only supported on linux")
}
