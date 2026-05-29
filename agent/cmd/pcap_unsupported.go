//go:build !windows || (windows && !amd64)

package main

import "fmt"

func (a *Agent) runPCAPPacketCapture() error {
	return fmt.Errorf("pcap capture is only used by the windows agent")
}
