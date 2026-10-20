//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// listenRaw reads IPv4 UDP packets with a raw socket. ly_probe currently
// exports NetFlow v9 with a checksum that the kernel considers invalid on the
// loopback path; a normal UDP socket silently drops those datagrams. A raw
// socket still receives them, so the probe evidence chain is preserved.
func listenRaw(ctx context.Context, port uint16, collector *Collector) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: int(port)}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	buf := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n < 28 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+8 {
			continue
		}
		if binary.BigEndian.Uint16(buf[ihl+2:ihl+4]) != port {
			continue
		}
		remote := &net.UDPAddr{IP: net.IPv4(buf[12], buf[13], buf[14], buf[15])}
		if source, ok := from.(*syscall.SockaddrInet4); ok {
			remote.IP = net.IPv4(source.Addr[0], source.Addr[1], source.Addr[2], source.Addr[3])
		}
		collector.handle(ctx, append([]byte(nil), buf[ihl+8:n]...), remote)
	}
}
