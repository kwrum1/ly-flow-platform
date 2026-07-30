package rulelifecycle

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type pinnedAddressKey struct{}

type Fetcher struct {
	policy   FetchPolicy
	resolver Resolver
	client   *http.Client
}

func NewFetcher(policy FetchPolicy, resolver Resolver, dial DialContext) (*Fetcher, error) {
	if len(policy.AllowedSchemes) == 0 || len(policy.AllowedDomains) == 0 || policy.MaxBytes <= 0 || policy.Timeout <= 0 || policy.MaxRedirects < 0 {
		return nil, fmt.Errorf("invalid fetch policy: %w", ErrURLPolicy)
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		netDialer := &net.Dialer{Timeout: policy.Timeout}
		dial = netDialer.DialContext
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			pinned, ok := ctx.Value(pinnedAddressKey{}).(string)
			if !ok || pinned == "" {
				return nil, fmt.Errorf("missing validated address: %w", ErrAddressPolicy)
			}
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("split destination: %w", err)
			}
			return dial(ctx, network, net.JoinHostPort(pinned, port))
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   policy.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Fetcher{policy: policy, resolver: resolver, client: client}, nil
}

func (f *Fetcher) Fetch(ctx context.Context, pin SourcePin) (FetchedSource, error) {
	if err := validatePin(pin); err != nil {
		return FetchedSource{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.policy.Timeout)
	defer cancel()
	current := pin.URL
	for redirects := 0; ; redirects++ {
		parsed, address, err := f.validateHop(ctx, current)
		if err != nil {
			return FetchedSource{}, err
		}
		requestCtx := context.WithValue(ctx, pinnedAddressKey{}, address.String())
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return FetchedSource{}, fmt.Errorf("create source request: %w", err)
		}
		request.Header.Set("User-Agent", "lyflow-rule-sync/2")
		response, err := f.client.Do(request)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return FetchedSource{}, fmt.Errorf("fetch %s: %w", parsed.Hostname(), ErrTimeout)
			}
			return FetchedSource{}, fmt.Errorf("fetch %s: %w", parsed.Hostname(), err)
		}
		if isRedirect(response.StatusCode) {
			location, locationErr := response.Location()
			closeErr := response.Body.Close()
			if locationErr != nil {
				return FetchedSource{}, fmt.Errorf("parse redirect: %w", locationErr)
			}
			if closeErr != nil {
				return FetchedSource{}, fmt.Errorf("close redirect response: %w", closeErr)
			}
			if redirects >= f.policy.MaxRedirects {
				return FetchedSource{}, fmt.Errorf("redirect cap exceeded: %w", ErrURLPolicy)
			}
			current = parsed.ResolveReference(location).String()
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			_ = response.Body.Close()
			return FetchedSource{}, fmt.Errorf("source returned HTTP %d", response.StatusCode)
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, f.policy.MaxBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil {
			if errors.Is(readErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return FetchedSource{}, fmt.Errorf("read %s: %w", parsed.Hostname(), ErrTimeout)
			}
			return FetchedSource{}, fmt.Errorf("read source: %w", readErr)
		}
		if closeErr != nil {
			return FetchedSource{}, fmt.Errorf("close source response: %w", closeErr)
		}
		if int64(len(content)) > f.policy.MaxBytes {
			return FetchedSource{}, ErrSizeLimit
		}
		actual := sha256.Sum256(content)
		expected, err := hex.DecodeString(strings.ToLower(pin.SHA256))
		if err != nil || subtle.ConstantTimeCompare(actual[:], expected) != 1 {
			return FetchedSource{}, ErrDigestMismatch
		}
		return FetchedSource{Pin: pin, FinalURL: parsed.String(), Content: content, Redirects: redirects, verified: true}, nil
	}
}

func (f *Fetcher) validateHop(ctx context.Context, rawURL string) (*url.URL, net.IP, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" || parsed.User != nil {
		return nil, nil, fmt.Errorf("invalid absolute source URL: %w", ErrURLPolicy)
	}
	if !containsFold(f.policy.AllowedSchemes, parsed.Scheme) || !domainAllowed(parsed.Hostname(), f.policy.AllowedDomains) {
		return nil, nil, fmt.Errorf("source %s://%s: %w", parsed.Scheme, parsed.Hostname(), ErrURLPolicy)
	}
	if parsed.Port() != "" {
		if _, err := strconv.ParseUint(parsed.Port(), 10, 16); err != nil {
			return nil, nil, fmt.Errorf("invalid source port: %w", ErrURLPolicy)
		}
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, nil, fmt.Errorf("local source hostname: %w", ErrURLPolicy)
	}
	addresses, err := f.resolver.LookupIP(ctx, "ip", parsed.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, nil, fmt.Errorf("resolve source host: %w", ErrAddressPolicy)
	}
	for _, address := range addresses {
		if address == nil || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast() || address.Equal(net.ParseIP("100.100.100.200")) {
			return nil, nil, fmt.Errorf("source resolves to %s: %w", address, ErrAddressPolicy)
		}
	}
	return parsed, addresses[0], nil
}

func validatePin(pin SourcePin) error {
	if len(pin.SHA256) != sha256.Size*2 {
		return ErrRevision
	}
	expected, err := hex.DecodeString(strings.ToLower(pin.SHA256))
	if err != nil {
		return fmt.Errorf("decode source digest: %w", ErrDigestMismatch)
	}
	const payloadDigestPrefix = "payload-sha256:"
	if strings.HasPrefix(pin.Revision, payloadDigestPrefix) {
		payloadDigest, decodeErr := hex.DecodeString(strings.TrimPrefix(pin.Revision, payloadDigestPrefix))
		if decodeErr != nil || len(payloadDigest) != sha256.Size {
			return ErrRevision
		}
		if subtle.ConstantTimeCompare(payloadDigest, expected) != 1 {
			return ErrDigestMismatch
		}
		return nil
	}
	if len(pin.Revision) == 0 || len(pin.Revision) > 128 || strings.HasPrefix(strings.ToLower(pin.Revision), "catalog-") {
		return ErrRevision
	}
	for _, character := range pin.Revision {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return ErrRevision
		}
	}
	return nil
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func domainAllowed(host string, allowed []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, domain := range allowed {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}
