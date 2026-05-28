module ly-flow-platform/agent

go 1.22

require (
	github.com/google/gopacket v1.1.19
	github.com/lyflow/ly-flow-platform v0.0.0
	github.com/redis/go-redis/v9 v9.5.1
	golang.org/x/net v0.22.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.36.4
)

replace github.com/lyflow/ly-flow-platform => ../pkg

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
)
