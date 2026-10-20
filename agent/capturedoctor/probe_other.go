//go:build !linux

package capturedoctor

import (
	"errors"
	"time"
)

type LinuxProbe struct{}

var errUnsupported = errors.New("capturedoctor: runtime probe is supported on Linux only")

func (LinuxProbe) Now() time.Time { return time.Now() }

func (LinuxProbe) Interface(string) (InterfaceInfo, error) {
	return InterfaceInfo{}, errUnsupported
}

func (LinuxProbe) Softnet() (SoftnetInfo, error) {
	return SoftnetInfo{}, errUnsupported
}

func (LinuxProbe) Ethtool(string) (EthtoolInfo, error) {
	return EthtoolInfo{}, errUnsupported
}

func (LinuxProbe) Process(string, string) (ProcessInfo, error) {
	return ProcessInfo{}, errUnsupported
}

func (LinuxProbe) PFRing() bool { return false }
