// Package fanout models the per-flow sharding contract for the LyFlow traffic
// engine prototype.
//
// The contract is deliberately smaller than a capture engine:
//
//   - Key canonicalises a bidirectional five-tuple, so both directions of a
//     flow produce the same bytes and therefore the same hash.
//   - Hash is a stable FNV-1a hash over those bytes. It is not the kernel
//     PACKET_FANOUT hash and not Suricata's cluster_flow hash; those are
//     private to each engine and must not be treated as a shared key.
//   - Shard maps the hash to a worker slot with a fixed modulus. A flow keeps
//     the same slot while the worker count is unchanged.
//
// Sharding is per engine family. A Suricata worker group and a lyprobe worker
// group must each receive 100% of the mirrored traffic and shard it
// independently. They must never divide flows between them, otherwise both
// engines lose half of their coverage.
package fanout

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// maxKeyBytes is one family byte plus one address plus one port per endpoint,
// plus one protocol byte.
const maxKeyBytes = 1 + 16 + 2 + 1 + 16 + 2 + 1

// Key is a bidirectional five-tuple. Addresses may be IPv4, IPv6, or
// IPv4-mapped IPv6; Canonical removes the 4-in-6 mapping first.
type Key struct {
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// NewKey builds a key from addresses in string form. It is a convenience for
// tests, fixtures, and command-line tools.
func NewKey(src, dst string, srcPort, dstPort uint16, proto uint8) (Key, error) {
	srcAddr, err := netip.ParseAddr(src)
	if err != nil {
		return Key{}, fmt.Errorf("parse source address %q: %w", src, err)
	}
	dstAddr, err := netip.ParseAddr(dst)
	if err != nil {
		return Key{}, fmt.Errorf("parse destination address %q: %w", dst, err)
	}
	return Key{Src: srcAddr, Dst: dstAddr, SrcPort: srcPort, DstPort: dstPort, Proto: proto}, nil
}

// Reverse swaps the two endpoints without canonicalising.
func (k Key) Reverse() Key {
	return Key{Src: k.Dst, Dst: k.Src, SrcPort: k.DstPort, DstPort: k.SrcPort, Proto: k.Proto}
}

// Canonical returns the direction-independent form of the key. Endpoints are
// ordered by address bytes and then by port, so A->B and B->A collapse to the
// same value even when both endpoints share an IP address.
func (k Key) Canonical() Key {
	k.Src = k.Src.Unmap()
	k.Dst = k.Dst.Unmap()
	if endpointLess(k.Dst, k.DstPort, k.Src, k.SrcPort) {
		k.Src, k.Dst = k.Dst, k.Src
		k.SrcPort, k.DstPort = k.DstPort, k.SrcPort
	}
	return k
}

func endpointLess(aAddr netip.Addr, aPort uint16, bAddr netip.Addr, bPort uint16) bool {
	if cmp := aAddr.Compare(bAddr); cmp != 0 {
		return cmp < 0
	}
	return aPort < bPort
}

// Hash returns the FNV-1a 64-bit hash of the canonical five-tuple. The value is
// stable across processes and Go versions because the encoding is explicit.
// Changing this function changes every flow's shard; treat it as a schema.
func (k Key) Hash() uint64 {
	k = k.Canonical()
	var buf [maxKeyBytes]byte
	n := k.encodeCanonical(buf[:])

	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, b := range buf[:n] {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}

// encodeCanonical writes family-tagged addresses, big-endian ports, and the
// protocol into dst. It returns the number of bytes written.
func (k Key) encodeCanonical(dst []byte) int {
	n := 0
	appendAddr := func(addr netip.Addr) {
		if addr.Is4() {
			dst[n] = 4
			n++
			v4 := addr.As4()
			copy(dst[n:], v4[:])
			n += len(v4)
			return
		}
		dst[n] = 6
		n++
		v16 := addr.As16()
		copy(dst[n:], v16[:])
		n += len(v16)
	}
	appendPort := func(port uint16) {
		binary.BigEndian.PutUint16(dst[n:], port)
		n += 2
	}

	appendAddr(k.Src)
	appendPort(k.SrcPort)
	appendAddr(k.Dst)
	appendPort(k.DstPort)
	dst[n] = k.Proto
	n++
	return n
}

// Shard returns the worker slot for the flow. It panics when workers <= 0,
// because silently clamping would hide a deployment bug and remap live flows.
func (k Key) Shard(workers int) int {
	if workers <= 0 {
		panic(fmt.Sprintf("fanout: worker count must be positive, got %d", workers))
	}
	return int(k.Hash() % uint64(workers))
}

// Group is one engine family's worker set. Each engine family owns its own
// Group; the worker count is fixed for the lifetime of the capture process.
type Group struct {
	workers int
}

// NewGroup validates the worker count.
func NewGroup(workers int) (Group, error) {
	if workers <= 0 {
		return Group{}, errors.New("fanout: worker count must be positive")
	}
	return Group{workers: workers}, nil
}

// Workers returns the fixed worker count.
func (g Group) Workers() int { return g.workers }

// Worker assigns a flow to a worker. The assignment is a pure function of the
// canonical key and the worker count.
func (g Group) Worker(k Key) int { return k.Shard(g.workers) }

// Distribution counts flows per worker. It is used by tests and the demo to
// prove that multiple workers receive traffic.
func Distribution(keys []Key, workers int) ([]int, error) {
	if workers <= 0 {
		return nil, errors.New("fanout: worker count must be positive")
	}
	counts := make([]int, workers)
	for _, k := range keys {
		counts[k.Shard(workers)]++
	}
	return counts, nil
}

// Imbalance returns max(count)/mean(count) - 1. A perfectly even split is 0.
// It returns 0 for an empty slice and +Inf when every count is zero.
func Imbalance(counts []int) float64 {
	if len(counts) == 0 {
		return 0
	}
	total, max := 0, 0
	for _, c := range counts {
		total += c
		if c > max {
			max = c
		}
	}
	if total == 0 {
		return 0
	}
	mean := float64(total) / float64(len(counts))
	return float64(max)/mean - 1
}

// PACKET_FANOUT modes and flags from linux/if_packet.h. They are exported so a
// deployment tool can build the same setsockopt argument that the kernel and
// Suricata use. They do not affect Hash or Shard.
const (
	FanoutHash         uint16 = 0
	FanoutLoadBalance  uint16 = 1
	FanoutCPU          uint16 = 2
	FanoutRollover     uint16 = 3
	FanoutRandom       uint16 = 4
	FanoutQueueMapping uint16 = 5
	FanoutCBPF         uint16 = 6
	FanoutEBPF         uint16 = 7

	FanoutFlagRollover       uint16 = 0x1000
	FanoutFlagUniqueID       uint16 = 0x2000
	FanoutFlagIgnoreOutgoing uint16 = 0x4000
	FanoutFlagDefrag         uint16 = 0x8000
)

// FanoutArg builds the PACKET_FANOUT setsockopt argument:
// (group ID << 16) | mode | flags.
func FanoutArg(groupID, mode, flags uint16) int {
	return int(groupID)<<16 | int(mode) | int(flags)
}
