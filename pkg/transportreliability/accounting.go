package transportreliability

import "sync/atomic"

type Accounting struct {
	received     atomic.Uint64
	materialized atomic.Uint64
	spooled      atomic.Uint64
	deadlettered atomic.Uint64
	pending      atomic.Uint64
	losses       atomic.Uint64
}

type AccountingSnapshot struct {
	Received     uint64 `json:"received"`
	Materialized uint64 `json:"materialized"`
	Spooled      uint64 `json:"spooled"`
	Deadlettered uint64 `json:"deadlettered"`
	Pending      uint64 `json:"pending"`
	Losses       uint64 `json:"losses"`
}

func (accounting *Accounting) Received() {
	accounting.received.Add(1)
	accounting.pending.Add(1)
}

func (accounting *Accounting) Materialized() {
	accounting.materialized.Add(1)
	accounting.resolve()
}

func (accounting *Accounting) Spooled() {
	accounting.spooled.Add(1)
	accounting.resolve()
}

func (accounting *Accounting) Deadlettered() {
	accounting.deadlettered.Add(1)
	accounting.resolve()
}

func (accounting *Accounting) Lost() {
	accounting.losses.Add(1)
}

func (accounting *Accounting) resolve() {
	for {
		current := accounting.pending.Load()
		if current == 0 || accounting.pending.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (accounting *Accounting) Snapshot() AccountingSnapshot {
	return AccountingSnapshot{
		Received: accounting.received.Load(), Materialized: accounting.materialized.Load(),
		Spooled: accounting.spooled.Load(), Deadlettered: accounting.deadlettered.Load(),
		Pending: accounting.pending.Load(), Losses: accounting.losses.Load(),
	}
}

func (snapshot AccountingSnapshot) Valid() bool {
	return snapshot.Received == snapshot.Materialized+snapshot.Spooled+snapshot.Deadlettered+snapshot.Pending
}

func (snapshot AccountingSnapshot) Metrics() map[string]uint64 {
	return map[string]uint64{
		"lyflow_transport_received_total":     snapshot.Received,
		"lyflow_transport_materialized_total": snapshot.Materialized,
		"lyflow_transport_spooled_total":      snapshot.Spooled,
		"lyflow_transport_deadlettered_total": snapshot.Deadlettered,
		"lyflow_transport_pending":            snapshot.Pending,
		"lyflow_transport_losses":             snapshot.Losses,
	}
}
