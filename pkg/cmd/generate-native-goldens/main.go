package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func main() {
	data, err := os.ReadFile("contracts/testdata/source-fixtures.json")
	if err != nil {
		fail("read source fixtures", err)
	}
	var fixtures []contracts.SourceFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		fail("decode source fixtures", err)
	}
	ingestedAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	golden := make(map[contracts.EventSource]json.RawMessage, len(fixtures))
	for _, fixture := range fixtures {
		event, _, err := contracts.NormalizeFixture(fixture, contracts.PrincipalIdentity("agent-1"), ingestedAt)
		if err != nil {
			fail("normalize "+string(fixture.Source), err)
		}
		encoded, err := contracts.MarshalCanonical(event)
		if err != nil {
			fail("marshal "+string(fixture.Source), err)
		}
		golden[fixture.Source] = encoded
	}
	encoded, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		fail("encode canonical goldens", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile("contracts/testdata/canonical-events.golden.json", encoded, 0o644); err != nil {
		fail("write canonical goldens", err)
	}
}

func fail(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
