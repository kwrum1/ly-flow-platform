package rulelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type staticResolver map[string][]net.IP

func (r staticResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	ips, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Name: host, Err: "fixture has no address"}
	}
	return ips, nil
}

func TestFetcher_fetches_pinned_bundle_through_allowlisted_redirect(t *testing.T) {
	// Given
	bundle := []byte(`{"version":"rev-1","rules":[{"id":"r1","name":"benign","category":"runtime","severity":"low","field":"message","operator":"contains","value":"fixture"}]}`)
	digest := sha256Hex(bundle)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/start":
			http.Redirect(w, request, "http://rules.example.test"+request.URL.Query().Get("port")+"/bundle", http.StatusFound)
		case "/bundle":
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split fixture address: %v", err)
	}
	fetcher := newTestFetcher(t, server, staticResolver{"rules.example.test": {net.ParseIP("192.0.2.10")}}, FetchPolicy{
		AllowedSchemes: []string{"http"}, AllowedDomains: []string{"rules.example.test"},
		MaxBytes: 1 << 20, Timeout: time.Second, MaxRedirects: 2,
	})
	pin := SourcePin{URL: "http://rules.example.test:" + port + "/start?port=:" + port, Revision: "rev-1", SHA256: digest}

	// When
	fetched, err := fetcher.Fetch(context.Background(), pin)

	// Then
	if err != nil {
		t.Fatalf("fetch pinned source: %v", err)
	}
	if string(fetched.Content) != string(bundle) || fetched.Redirects != 1 || fetched.Pin != pin {
		t.Fatalf("unexpected fetch result: %#v", fetched)
	}
}

func TestFetcher_rejects_disallowed_redirect_before_following_it(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, "http://metadata.invalid/latest", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split fixture address: %v", err)
	}
	fetcher := newTestFetcher(t, server, staticResolver{
		"rules.example.test": {net.ParseIP("192.0.2.10")},
		"metadata.invalid":   {net.ParseIP("169.254.169.254")},
	}, FetchPolicy{AllowedSchemes: []string{"http"}, AllowedDomains: []string{"rules.example.test"}, MaxBytes: 1024, Timeout: time.Second, MaxRedirects: 2})

	// When
	_, err = fetcher.Fetch(context.Background(), SourcePin{URL: "http://rules.example.test:" + port + "/start", Revision: "rev-1", SHA256: strings.Repeat("0", 64)})

	// Then
	if !errors.Is(err, ErrURLPolicy) {
		t.Fatalf("redirect error = %v, want ErrURLPolicy", err)
	}
}

func TestFetcher_rejects_non_public_resolved_addresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "loopback", ip: "127.0.0.1"},
		{name: "private", ip: "10.1.2.3"},
		{name: "link-local", ip: "169.254.20.1"},
		{name: "metadata", ip: "169.254.169.254"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			fetcher, err := NewFetcher(FetchPolicy{AllowedSchemes: []string{"https"}, AllowedDomains: []string{"rules.example.test"}, MaxBytes: 1024, Timeout: time.Second, MaxRedirects: 1}, staticResolver{"rules.example.test": {net.ParseIP(test.ip)}}, nil)
			if err != nil {
				t.Fatalf("new fetcher: %v", err)
			}

			// When
			_, fetchErr := fetcher.Fetch(context.Background(), SourcePin{URL: "https://rules.example.test/bundle", Revision: "rev-1", SHA256: strings.Repeat("0", 64)})

			// Then
			if !errors.Is(fetchErr, ErrAddressPolicy) {
				t.Fatalf("address error = %v, want ErrAddressPolicy", fetchErr)
			}
		})
	}
}

func TestFetcher_enforces_digest_size_and_timeout_caps(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		max     int64
		timeout time.Duration
		digest  string
		wait    bool
		want    error
	}{
		{name: "digest", body: "bundle", max: 1024, timeout: time.Second, digest: strings.Repeat("0", 64), want: ErrDigestMismatch},
		{name: "size", body: strings.Repeat("x", 65), max: 64, timeout: time.Second, digest: sha256Hex([]byte(strings.Repeat("x", 65))), want: ErrSizeLimit},
		{name: "timeout", max: 64, timeout: 20 * time.Millisecond, digest: strings.Repeat("0", 64), wait: true, want: ErrTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if test.wait {
					w.WriteHeader(http.StatusOK)
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
					<-request.Context().Done()
					return
				}
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatalf("split fixture address: %v", err)
			}
			fetcher := newTestFetcher(t, server, staticResolver{"rules.example.test": {net.ParseIP("192.0.2.10")}}, FetchPolicy{AllowedSchemes: []string{"http"}, AllowedDomains: []string{"rules.example.test"}, MaxBytes: test.max, Timeout: test.timeout, MaxRedirects: 1})

			// When
			_, fetchErr := fetcher.Fetch(context.Background(), SourcePin{URL: "http://rules.example.test:" + port + "/bundle", Revision: "rev-1", SHA256: test.digest})

			// Then
			if !errors.Is(fetchErr, test.want) {
				t.Fatalf("fetch error = %v, want %v", fetchErr, test.want)
			}
		})
	}
}

func newTestFetcher(t *testing.T, server *httptest.Server, resolver Resolver, policy FetchPolicy) *Fetcher {
	t.Helper()
	dialer := &net.Dialer{Timeout: time.Second}
	fetcher, err := NewFetcher(policy, resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	return fetcher
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
