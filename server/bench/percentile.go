package bench

import (
	"sort"
	"time"
)

// Percentile returns the nearest-rank percentile for a duration sample.
func Percentile(samples []time.Duration, percentile float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	if percentile <= 0 {
		percentile = 0
	}
	if percentile > 100 {
		percentile = 100
	}
	values := append([]time.Duration(nil), samples...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	rank := int(percentile/100*float64(len(values)) + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(values) {
		rank = len(values)
	}
	return values[rank-1]
}
