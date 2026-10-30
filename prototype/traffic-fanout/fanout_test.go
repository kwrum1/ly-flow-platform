package fanout

import (
	"math/rand"
	"net/netip"
	"testing"
)

// syntheticKeys returns a deterministic mix of client/server flows. Ephemeral
// client ports plus repeated server ports approximate a server-zone mirror.
func syntheticKeys(n int) []Key {
	rng := rand.New(rand.NewSource(42))
	destPorts := []uint16{80, 443, 22, 8080, 53, 3306}
	keys := make([]Key, n)
	for i := range keys {
		client := netip.AddrFrom4([4]byte{10, 20, byte(rng.Intn(8)), byte(rng.Intn(250) + 1)})
		server := netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(40) + 1)})
		proto := uint8(6)
		if rng.Intn(5) == 0 {
			proto = 17
		}
		keys[i] = Key{
			Src:     client,
			Dst:     server,
			SrcPort: uint16(1024 + rng.Intn(60000)),
			DstPort: destPorts[rng.Intn(len(destPorts))],
			Proto:   proto,
		}
	}
	return keys
}

func ipv6Keys() []Key {
	return []Key{
		{
			Src:     netip.MustParseAddr("2001:db8::1"),
			Dst:     netip.MustParseAddr("2001:db8::2"),
			SrcPort: 51000,
			DstPort: 443,
			Proto:   6,
		},
		{
			Src:     netip.MustParseAddr("2001:db8:1::10"),
			Dst:     netip.MustParseAddr("2001:db8:2::20"),
			SrcPort: 53,
			DstPort: 5353,
			Proto:   17,
		},
	}
}

func TestReverseIsSymmetric(t *testing.T) {
	keys := append(syntheticKeys(2000), ipv6Keys()...)
	for i, key := range keys {
		rev := key.Reverse()
		if key.Canonical() != rev.Canonical() {
			t.Fatalf("key %d: canonical mismatch:\n forward=%+v\n reverse=%+v", i, key.Canonical(), rev.Canonical())
		}
		if key.Hash() != rev.Hash() {
			t.Fatalf("key %d: hash mismatch: forward=%d reverse=%d", i, key.Hash(), rev.Hash())
		}
		for workers := 1; workers <= 16; workers++ {
			if got, want := key.Shard(workers), rev.Shard(workers); got != want {
				t.Fatalf("key %d: shard mismatch at %d workers: forward=%d reverse=%d", i, workers, got, want)
			}
		}
		if key.Reverse().Reverse() != key {
			t.Fatalf("key %d: double reverse changed the key", i)
		}
	}
}

func TestSameAddressDifferentPortsIsSymmetric(t *testing.T) {
	// Hairpin/localhost traffic can share an address on both endpoints, so the
	// canonical order must fall back to ports.
	key := Key{
		Src:     netip.MustParseAddr("127.0.0.1"),
		Dst:     netip.MustParseAddr("127.0.0.1"),
		SrcPort: 54321,
		DstPort: 8080,
		Proto:   6,
	}
	if key.Hash() != key.Reverse().Hash() {
		t.Fatalf("same-address flow is not symmetric: %d != %d", key.Hash(), key.Reverse().Hash())
	}
}

func TestIPv4MappedAddressNormalised(t *testing.T) {
	mapped := Key{
		Src:     netip.MustParseAddr("::ffff:10.0.0.1"),
		Dst:     netip.MustParseAddr("::ffff:203.0.113.5"),
		SrcPort: 40000,
		DstPort: 443,
		Proto:   6,
	}
	plain := Key{
		Src:     netip.MustParseAddr("10.0.0.1"),
		Dst:     netip.MustParseAddr("203.0.113.5"),
		SrcPort: 40000,
		DstPort: 443,
		Proto:   6,
	}
	if mapped.Canonical() != plain.Canonical() {
		t.Fatalf("IPv4-mapped key did not canonicalise to the plain IPv4 key")
	}
	if mapped.Hash() != plain.Hash() {
		t.Fatalf("IPv4-mapped key hash %d != plain hash %d", mapped.Hash(), plain.Hash())
	}
}

func TestFlowPinnedToWorker(t *testing.T) {
	group, err := NewGroup(8)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	keys := syntheticKeys(200)
	assigned := make(map[Key]int)
	for _, key := range keys {
		canonical := key.Canonical()
		want := group.Worker(key)
		for i := 0; i < 50; i++ {
			// Every packet of the flow, in either direction, lands on the same
			// worker for as long as the worker count is unchanged.
			sample := key
			if i%2 == 1 {
				sample = key.Reverse()
			}
			if got := group.Worker(sample); got != want {
				t.Fatalf("flow %+v moved from worker %d to %d", canonical, want, got)
			}
		}
		if prev, ok := assigned[canonical]; ok && prev != want {
			t.Fatalf("flow %+v was assigned to both %d and %d", canonical, prev, want)
		}
		assigned[canonical] = want
	}
}

func TestFlowsSpreadAcrossWorkers(t *testing.T) {
	keys := syntheticKeys(20000)
	for _, workers := range []int{2, 4, 8, 16} {
		counts, err := Distribution(keys, workers)
		if err != nil {
			t.Fatalf("Distribution(%d): %v", workers, err)
		}
		mean := float64(len(keys)) / float64(workers)
		for worker, count := range counts {
			if count == 0 {
				t.Fatalf("%d workers: worker %d received no flows", workers, worker)
			}
			if float64(count) < mean*0.85 || float64(count) > mean*1.15 {
				t.Fatalf("%d workers: worker %d got %d flows (mean %.0f, counts %v)", workers, worker, count, mean, counts)
			}
		}
		if got := Imbalance(counts); got > 0.15 {
			t.Fatalf("%d workers: imbalance %.3f exceeds 0.15 (counts %v)", workers, got, counts)
		}
	}
}

func TestShardRejectsInvalidWorkerCount(t *testing.T) {
	key := syntheticKeys(1)[0]
	for _, workers := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("Shard(%d) did not panic", workers)
				}
			}()
			_ = key.Shard(workers)
		}()
	}
	if _, err := NewGroup(0); err == nil {
		t.Fatal("NewGroup(0) returned nil error")
	}
	if _, err := Distribution(nil, 0); err == nil {
		t.Fatal("Distribution with 0 workers returned nil error")
	}
}

func TestWorkerCountChangeRemapsActiveFlows(t *testing.T) {
	// Scaling the worker count is not free: live flows are rehashed. This test
	// documents the cost so operators scale during a maintenance window rather
	// than by adding a thread to a running capture.
	keys := syntheticKeys(5000)
	remapped := 0
	for _, key := range keys {
		if key.Shard(4) != key.Shard(6) {
			remapped++
		}
	}
	ratio := float64(remapped) / float64(len(keys))
	if ratio < 0.5 || ratio > 0.95 {
		t.Fatalf("remap ratio %.3f outside expected 0.5..0.95", ratio)
	}
}

func TestFanoutArg(t *testing.T) {
	arg := FanoutArg(10001, FanoutHash, FanoutFlagDefrag|FanoutFlagRollover)
	want := 10001<<16 | 0x9000
	if arg != want {
		t.Fatalf("FanoutArg = %#x, want %#x", arg, want)
	}
}

func TestHashKnownVector(t *testing.T) {
	// This value pins the canonical encoding and hash algorithm. Updating it
	// means every flow changes shard, which is a deployment-visible event.
	key, err := NewKey("10.0.0.1", "203.0.113.5", 40000, 443, 6)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	const want uint64 = 4303795920754287703
	if got := key.Hash(); got != want {
		t.Fatalf("hash = %d, want %d", got, want)
	}
}
