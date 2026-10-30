//go:build linux

package fanout

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

const (
	solPacket    = 263 // SOL_PACKET
	packetFanout = 18  // PACKET_FANOUT
)

// OpenFanoutSocket joins ifname to an AF_PACKET fanout group.
//
// Every socket in a group must use the same group ID, mode, and flags. This is
// a membership helper only: it does not mmap a TPACKET ring and does not parse
// packets. It exists so a test host can verify that N processes actually land
// in the same kernel group before any capture code is changed.
//
// It requires CAP_NET_RAW (or root). A group must contain sockets from exactly
// one engine family. Adding a second engine's sockets to the same group makes
// the kernel split packets between the engines instead of giving each engine
// the full flow set.
func OpenFanoutSocket(ifname string, groupID uint16, mode, flags uint16) (*os.File, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("fanout: interface %q: %w", ifname, err)
	}

	proto := htons(syscall.ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("fanout: create AF_PACKET socket: %w", err)
	}
	closeOnError := func(cause error) (*os.File, error) {
		_ = syscall.Close(fd)
		return nil, cause
	}

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  iface.Index,
	}); err != nil {
		return closeOnError(fmt.Errorf("fanout: bind %q: %w", ifname, err))
	}

	if err := syscall.SetsockoptInt(fd, solPacket, packetFanout, FanoutArg(groupID, mode, flags)); err != nil {
		return closeOnError(fmt.Errorf("fanout: join group %d on %q: %w", groupID, ifname, err))
	}

	return os.NewFile(uintptr(fd), "af_packet:"+ifname), nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
