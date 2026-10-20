//go:build !windows || (windows && !amd64)

package main

import "fmt"

func (a *Agent) runPCAPPacketCapture() error {
	return fmt.Errorf("pcap capture is not supported on this platform")
}
