module ly-flow-platform/agent

go 1.26.5

require (
	github.com/google/gopacket v1.1.19
	github.com/lyflow/ly-flow-platform v0.0.0
	github.com/redis/go-redis/v9 v9.6.3
	golang.org/x/net v0.55.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.10
)

replace github.com/lyflow/ly-flow-platform => ../pkg

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
