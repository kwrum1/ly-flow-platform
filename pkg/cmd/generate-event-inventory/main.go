package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lyflow/ly-flow-platform/eventinventory"
)

func main() {
	inventory, err := eventinventory.Scan("..")
	if err != nil {
		fail("scan event inventory", err)
	}
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		fail("encode event inventory", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile("../docs/generated/event-contract-inventory.json", data, 0o644); err != nil {
		fail("write event inventory", err)
	}
}

func fail(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
