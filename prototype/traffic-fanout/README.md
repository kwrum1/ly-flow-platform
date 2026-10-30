# traffic-fanout prototype

Status: **design prototype only. Not deployed, not wired into any service.**

This module proves the sharding contract that a future capture shim must
satisfy. It does not capture packets and it does not change Suricata or
ly_probe.

## What it proves

| Property | Test |
| --- | --- |
| Both directions of a flow hash to the same value/shard | `TestReverseIsSymmetric`, `TestSameAddressDifferentPortsIsSymmetric` |
| A flow stays on one worker while the worker count is fixed | `TestFlowPinnedToWorker` |
| Different flows spread over multiple workers | `TestFlowsSpreadAcrossWorkers`, `cmd/fanout-demo` |
| IPv4 and IPv4-mapped IPv6 are the same flow | `TestIPv4MappedAddressNormalised` |
| Changing the worker count remaps live flows | `TestWorkerCountChangeRemapsActiveFlows` |
| Hash/encoding changes are visible | `TestHashKnownVector` |
| `PACKET_FANOUT` argument layout is correct | `TestFanoutArg` |

## Layout

```text
fanout.go              canonical five-tuple, FNV-1a hash, shard/group model
fanout_test.go         the table above
fanout_linux.go        AF_PACKET + PACKET_FANOUT membership helper (linux only)
cmd/fanout-demo/       deterministic distribution report
```

`fanout.go` is pure Go and has no dependencies. The hash is a reference
implementation for a future user-space shim or test tool; it is **not** the
kernel `PACKET_FANOUT` hash and **not** Suricata's `cluster_flow` hash.

## Run

The module is intentionally outside `go.work`, so tests must disable the
workspace when run from this directory:

```bash
cd prototype/traffic-fanout
GOWORK=off go test ./...
GOWORK=off go run ./cmd/fanout-demo
```

Linux build check (does not run):

```bash
GOWORK=off GOOS=linux GOARCH=amd64 go build ./...
```

`OpenFanoutSocket` requires `CAP_NET_RAW` and a host network namespace. It only
joins a group; it does not mmap a ring. It is compile-checked on Windows and
must be exercised on `TEST_HOST`, never on `.241`/`.8`, before any deployment.

## Rules of use

- A fanout group contains sockets from **one** engine family only.
- Suricata and lyprobe use different group IDs and each gets 100% of the
  mirrored traffic.
- Do not enable `PACKET_FANOUT_FLAG_ROLLOVER` for flow-based engines: rollover
  moves a full socket's packets to another worker and breaks flow affinity.
- Treat the worker count as a deployment constant. Adding a worker remaps most
  live flows.

See `docs/dev/TRAFFIC-ENGINE-PROTOTYPE.md` for the comparison and production
gate.
