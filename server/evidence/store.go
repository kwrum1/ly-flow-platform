// Package evidence stores immutable, content-addressed evidence bundles and
// artifacts for incident investigation. The filesystem backend is the
// single-node durable backend; the layout is deliberately object-store shaped
// so a SeaweedFS/S3 adapter can implement the same Store contract later.
package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("evidence: not found")
	ErrInvalid  = errors.New("evidence: invalid input")
)

type Artifact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MediaType string    `json:"media_type"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	ObjectKey string    `json:"object_key"`
}

type Bundle struct {
	ID          string    `json:"id"`
	IncidentID  string    `json:"incident_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	Schema      string    `json:"schema"`
	MediaType   string    `json:"media_type"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	EventUIDs   []string  `json:"event_uids,omitempty"`
	ArtifactIDs []string  `json:"artifact_ids,omitempty"`
	ObjectKey   string    `json:"object_key"`
}

type Store struct {
	root string
	mu   sync.Mutex
}

func New(root string) (*Store, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: evidence root is empty", ErrInvalid)
	}
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "bundles"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o700); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (store *Store) PutArtifact(name, mediaType string, data []byte) (Artifact, error) {
	if store == nil {
		return Artifact{}, fmt.Errorf("%w: store unavailable", ErrInvalid)
	}
	if len(data) == 0 {
		return Artifact{}, fmt.Errorf("%w: artifact is empty", ErrInvalid)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	artifact := Artifact{
		ID:        "art-" + digest,
		Name:      sanitizeName(name),
		MediaType: strings.TrimSpace(mediaType),
		SHA256:    digest,
		Size:      int64(len(data)),
		CreatedAt: now,
		ObjectKey: objectKey(digest),
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writeObject(artifact.ObjectKey, data); err != nil {
		return Artifact{}, err
	}
	metadata, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return Artifact{}, err
	}
	if err := writeAtomic(filepath.Join(store.root, "artifacts", artifact.ID+".json"), metadata); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

func (store *Store) GetArtifact(id string) (Artifact, []byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !strings.HasPrefix(id, "art-") {
		return Artifact{}, nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(store.root, "artifacts", id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return Artifact{}, nil, ErrNotFound
	}
	if err != nil {
		return Artifact{}, nil, err
	}
	var artifact Artifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return Artifact{}, nil, err
	}
	object, err := os.ReadFile(filepath.Join(store.root, "objects", artifact.ObjectKey))
	if err != nil {
		return Artifact{}, nil, err
	}
	return artifact, object, nil
}

func (store *Store) PutBundle(bundle Bundle, data []byte) (Bundle, error) {
	if store == nil {
		return Bundle{}, fmt.Errorf("%w: store unavailable", ErrInvalid)
	}
	if len(data) == 0 {
		return Bundle{}, fmt.Errorf("%w: bundle is empty", ErrInvalid)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	bundle.ID = "evb-" + digest[:24]
	bundle.Schema = "lyflow.evidence.bundle.v1"
	bundle.MediaType = "application/vnd.lyflow.evidence+json"
	bundle.SHA256 = digest
	bundle.Size = int64(len(data))
	bundle.CreatedAt = now
	bundle.ObjectKey = objectKey(digest)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writeObject(bundle.ObjectKey, data); err != nil {
		return Bundle{}, err
	}
	metadata, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return Bundle{}, err
	}
	if err := writeAtomic(filepath.Join(store.root, "bundles", bundle.ID+".json"), metadata); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (store *Store) ListBundles(limit int) ([]Bundle, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "bundles"))
	if err != nil {
		return nil, err
	}
	bundles := make([]Bundle, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(store.root, "bundles", entry.Name()))
		if err != nil {
			continue
		}
		var bundle Bundle
		if json.Unmarshal(data, &bundle) == nil {
			bundles = append(bundles, bundle)
		}
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].CreatedAt.After(bundles[j].CreatedAt) })
	if len(bundles) > limit {
		bundles = bundles[:limit]
	}
	return bundles, nil
}

func (store *Store) GetBundle(id string) (Bundle, []byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !strings.HasPrefix(id, "evb-") {
		return Bundle{}, nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(store.root, "bundles", id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return Bundle{}, nil, ErrNotFound
	}
	if err != nil {
		return Bundle{}, nil, err
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return Bundle{}, nil, err
	}
	object, err := os.ReadFile(filepath.Join(store.root, "objects", bundle.ObjectKey))
	if err != nil {
		return Bundle{}, nil, err
	}
	return bundle, object, nil
}

func (store *Store) writeObject(key string, data []byte) error {
	path := filepath.Join(store.root, "objects", key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(data) {
		return nil
	}
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp-" + randomSuffix()
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func objectKey(digest string) string {
	if len(digest) < 2 {
		return digest
	}
	return filepath.Join(digest[:2], digest)
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(filepath.Base(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "artifact.bin"
	}
	return name
}

func randomSuffix() string {
	var raw [6]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}
