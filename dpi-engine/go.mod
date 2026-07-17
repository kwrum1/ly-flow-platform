module ly-flow-platform/dpi-engine

go 1.26.5

require (
	github.com/google/gopacket v1.1.19
	github.com/lyflow/ly-flow-platform v0.0.0
	github.com/redis/go-redis/v9 v9.6.3
	golang.org/x/crypto v0.52.0
)

replace github.com/lyflow/ly-flow-platform => ../pkg

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/sys v0.45.0 // indirect
)
