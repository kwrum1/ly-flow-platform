module ly-flow-platform/security-engine

go 1.26.5

require (
	github.com/lyflow/ly-flow-platform v0.0.0
	github.com/redis/go-redis/v9 v9.6.3
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)

replace github.com/lyflow/ly-flow-platform => ../pkg
