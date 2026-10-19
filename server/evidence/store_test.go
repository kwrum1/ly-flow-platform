package evidence

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestStoreContentAddressedArtifactsAndBundles(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	artifact, err := store.PutArtifact("sample.pcap", "application/vnd.tcpdump.pcap", []byte("inert pcap bytes"))
	if err != nil {
		t.Fatalf("put artifact: %v", err)
	}
	got, payload, err := store.GetArtifact(artifact.ID)
	if err != nil || got.SHA256 != artifact.SHA256 || !bytes.Equal(payload, []byte("inert pcap bytes")) {
		t.Fatalf("get artifact: %+v %v", got, err)
	}
	bundle, err := store.PutBundle(Bundle{IncidentID: "incident-1", AgentID: "agent-1", ArtifactIDs: []string{artifact.ID}}, []byte(`{"schema":"lyflow.evidence.bundle.v1"}`))
	if err != nil {
		t.Fatalf("put bundle: %v", err)
	}
	if bundle.ID == "" || bundle.SHA256 == "" || bundle.ObjectKey == "" {
		t.Fatalf("bundle metadata incomplete: %+v", bundle)
	}
	items, err := store.ListBundles(10)
	if err != nil || len(items) != 1 || items[0].ID != bundle.ID {
		t.Fatalf("list bundles: %+v %v", items, err)
	}
	gotBundle, data, err := store.GetBundle(bundle.ID)
	if err != nil || gotBundle.SHA256 != bundle.SHA256 || string(data) != `{"schema":"lyflow.evidence.bundle.v1"}` {
		t.Fatalf("get bundle: %+v %v", gotBundle, err)
	}
}
