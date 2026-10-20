package evidence

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FilerObjectStore writes immutable objects through the SeaweedFS filer HTTP
// API. Metadata remains in the evidence store; only content bytes are remote.
type FilerObjectStore struct {
	base   string
	client *http.Client
}

func NewFilerObjectStore(base string) (*FilerObjectStore, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("%w: filer URL is empty", ErrInvalid)
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("%w: invalid filer URL: %v", ErrInvalid, err)
	}
	return &FilerObjectStore{base: base, client: &http.Client{Timeout: 20 * time.Second}}, nil
}

func (store *FilerObjectStore) Put(key string, data []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filerObjectName(key))
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, store.base+"/lyflow/evidence/"+filerObjectName(key), &body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := store.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("filer put %s: status=%d body=%s", key, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

func (store *FilerObjectStore) Get(key string) ([]byte, error) {
	response, err := store.client.Get(store.base + "/lyflow/evidence/" + filerObjectName(key))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("filer get %s: status=%d", key, response.StatusCode)
	}
	return io.ReadAll(response.Body)
}

func filerObjectName(key string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-")
	return replacer.Replace(key)
}
