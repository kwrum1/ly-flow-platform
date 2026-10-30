// Command fanout-demo prints the shard assignment for a deterministic synthetic
// traffic mix. It is a reporting aid for the prototype, not a capture tool.
package main

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"

	"github.com/lyflow/ly-flow-platform/prototype/traffic-fanout"
)

func main() {
	const (
		flows   = 4096
		workers = 8
	)
	keys := syntheticKeys(flows)

	fmt.Printf("fanout demo: %d synthetic flows, %d workers\n", flows, workers)
	fmt.Println("algorithm: FNV-1a 64 over canonical (family,addr,port)+(addr,port)+proto")

	symmetric := 0
	for _, key := range keys {
		if key.Hash() == key.Reverse().Hash() {
			symmetric++
		}
	}
	fmt.Printf("reverse-direction symmetry: %d/%d flows\n", symmetric, len(keys))

	counts, err := fanout.Distribution(keys, workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "distribution: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()
	fmt.Println("worker  flows  share")
	for worker, count := range counts {
		fmt.Printf("%6d  %5d  %5.1f%%\n", worker, count, 100*float64(count)/float64(len(keys)))
	}
	fmt.Printf("max/mean imbalance: %.3f\n", fanout.Imbalance(counts))

	fmt.Println()
	fmt.Println("sample flow assignments (reverse maps to the same worker):")
	for i := 0; i < 5; i++ {
		key := keys[i]
		rev := key.Reverse()
		fmt.Printf("  %s:%d -> %s:%d proto=%d : worker %d (reverse worker %d)\n",
			key.Src, key.SrcPort, key.Dst, key.DstPort, key.Proto,
			key.Shard(workers), rev.Shard(workers))
	}

	if symmetric != len(keys) {
		fmt.Fprintln(os.Stderr, "FAIL: some flows are not symmetric")
		os.Exit(1)
	}
	for worker, count := range counts {
		if count == 0 {
			fmt.Fprintf(os.Stderr, "FAIL: worker %d received no flows\n", worker)
			os.Exit(1)
		}
	}
	fmt.Println("\nPASS: symmetric hash, stable assignment, all workers used")
}

func syntheticKeys(n int) []fanout.Key {
	rng := rand.New(rand.NewSource(42))
	destPorts := []uint16{80, 443, 22, 8080, 53, 3306}
	keys := make([]fanout.Key, n)
	for i := range keys {
		proto := uint8(6)
		if rng.Intn(5) == 0 {
			proto = 17
		}
		keys[i] = fanout.Key{
			Src:     netip.AddrFrom4([4]byte{10, 20, byte(rng.Intn(8)), byte(rng.Intn(250) + 1)}),
			Dst:     netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(40) + 1)}),
			SrcPort: uint16(1024 + rng.Intn(60000)),
			DstPort: destPorts[rng.Intn(len(destPorts))],
			Proto:   proto,
		}
	}
	return keys
}
