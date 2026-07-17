// Package inspace implements the location-aware subset of the InSpace Cloud API
// shared by the cloud provider, CSI driver, and Karpenter provider.
package inspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultUserAgent   = "cloud-provider-inspace/dev"
	defaultHTTPTimeout = 5 * time.Minute
	defaultReadTimeout = 30 * time.Second
)

var (
	// ErrMutationBlocked is returned before an unsafe request can reach the network.
	ErrMutationBlocked = errors.New("inspace: mutation blocked for non-loopback API endpoint")
	// ErrMutationRedirect prevents net/http from replaying a POST, PUT, PATCH,
	// or DELETE at a redirect target. InSpace mutations do not expose an
	// idempotency-key contract, so even a same-origin 307/308 is ambiguous.
	ErrMutationRedirect = errors.New("inspace: mutation redirect blocked")
	// ErrCrossOriginRedirect prevents an API key from following redirects to a
	// different origin. This applies to read and write requests alike.
	ErrCrossOriginRedirect = errors.New("inspace: cross-origin redirect blocked")
	locationPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern            = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Options configures a Client. Mutating requests are safe by default: they are
// accepted only for literal loopback hosts (including localhost), such as an
// httptest server. Production controllers must deliberately opt in.
type Options struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	UserAgent  string

	// DangerouslyAllowMutations permits POST, PUT, PATCH and DELETE against a
	// non-loopback BaseURL. Never set this in discovery or smoke-test tooling.
	DangerouslyAllowMutations bool
}

// Client is safe for concurrent use.
type Client struct {
	baseURL                   *url.URL
	apiKey                    string
	httpClient                *http.Client
	userAgent                 string
	dangerouslyAllowMutations bool
}

// NewClient validates options without making a network request.
func NewClient(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("inspace: base URL is required")
	}
	baseURL, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("inspace: parse base URL: %w", err)
	}
	if (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, errors.New("inspace: base URL must be an absolute http(s) URL")
	}
	if baseURL.Scheme != "https" && !isLiteralLoopback(baseURL.Hostname()) {
		return nil, errors.New("inspace: non-loopback base URL must use HTTPS")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("inspace: base URL must not contain credentials, query, or fragment")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, errors.New("inspace: API key is required")
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		// VM creation is a synchronous API call and can legitimately take well
		// over 30 seconds. Callers may still supply a shorter client or context
		// deadline for mutations that need a tighter bound. GET requests receive
		// their own shorter per-request deadline in doBody.
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// Copy the caller's client so the safety policy cannot be bypassed by an
	// HTTP 307/308 redirect and so caller-owned configuration is not mutated.
	httpClientCopy := *httpClient
	originalCheckRedirect := httpClientCopy.CheckRedirect
	httpClientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) != 0 && isMutation(via[len(via)-1].Method) {
			return fmt.Errorf("%w: %s to %s", ErrMutationRedirect, via[len(via)-1].Method, req.URL.Redacted())
		}
		if !sameOrigin(baseURL, req.URL) {
			return fmt.Errorf("%w: %s", ErrCrossOriginRedirect, req.URL.Redacted())
		}
		if isMutation(req.Method) && !isLiteralLoopback(req.URL.Hostname()) && !opts.DangerouslyAllowMutations {
			return fmt.Errorf("%w: redirect to %s", ErrMutationBlocked, req.URL.Redacted())
		}
		if originalCheckRedirect != nil {
			return originalCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{
		baseURL:                   baseURL,
		apiKey:                    opts.APIKey,
		httpClient:                &httpClientCopy,
		userAgent:                 userAgent,
		dangerouslyAllowMutations: opts.DangerouslyAllowMutations,
	}, nil
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (c *Client) locationPath(location, resource string) (string, error) {
	if !locationPattern.MatchString(location) {
		return "", fmt.Errorf("inspace: invalid location %q", location)
	}
	return "/v1/" + location + "/" + strings.TrimLeft(resource, "/"), nil
}

func validateUUID(kind, value string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("inspace: invalid %s UUID %q", kind, value)
	}
	return nil
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isLiteralLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, form url.Values, out any) error {
	var body io.Reader
	contentType := ""
	if form != nil {
		body = bytes.NewBufferString(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	return c.doBody(ctx, method, path, query, body, contentType, out)
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, input, out any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("inspace: encode %s %s request: %w", method, path, err)
		}
		body = bytes.NewReader(data)
	}
	return c.doBody(ctx, method, path, query, body, "application/json", out)
}

func (c *Client) doBody(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, out any) error {
	if isMutation(method) && !isLiteralLoopback(c.baseURL.Hostname()) && !c.dangerouslyAllowMutations {
		return fmt.Errorf("%w: %s %s", ErrMutationBlocked, method, path)
	}
	if method == http.MethodGet && ctx != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultReadTimeout)
		defer cancel()
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("inspace: build request: %w", err)
	}
	req.Header.Set("apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("inspace: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("inspace: read %s %s response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(method, path, resp.StatusCode, data)
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("inspace: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// APIError is a normalized non-2xx API response. Retryable is only a scheduling
// hint: for POST, PUT, PATCH, and DELETE, no HTTP status proves that the
// mutation did not commit. Callers must resolve the outcome by authoritative
// readback before replaying or releasing durable ownership.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Message    string
	Retryable  bool
}

func (e *APIError) Error() string {
	return fmt.Sprintf("inspace: %s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

func newAPIError(method, path string, status int, data []byte) *APIError {
	message := strings.TrimSpace(string(data))
	var payload struct {
		Error   any            `json:"error"`
		Message string         `json:"message"`
		Errors  map[string]any `json:"errors"`
	}
	if json.Unmarshal(data, &payload) == nil {
		switch {
		case payload.Message != "":
			message = payload.Message
		case payload.Error != nil:
			message = fmt.Sprint(payload.Error)
		case len(payload.Errors) != 0:
			parts := make([]string, 0, len(payload.Errors))
			for key, value := range payload.Errors {
				parts = append(parts, fmt.Sprintf("%s: %v", key, value))
			}
			message = strings.Join(parts, "; ")
		}
	}
	if message == "" {
		message = http.StatusText(status)
	}
	return &APIError{
		StatusCode: status,
		Method:     method,
		Path:       path,
		Message:    message,
		Retryable: status == http.StatusRequestTimeout ||
			status == http.StatusTooManyRequests || status >= 500,
	}
}

// IsNotFound reports whether err represents an absent resource. InSpace uses
// HTTP 400 with a "No such virtual machine exists" message for some
// already-deleted VM lookups, so that exact semantic response is normalized
// alongside HTTP 404. Other "No such ... exists" errors can describe billing,
// network, or authorization state and must remain ordinary failures.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusNotFound {
		return true
	}
	message := strings.ToLower(strings.TrimSpace(apiErr.Message))
	message = strings.TrimSpace(strings.TrimPrefix(message, "error:"))
	if apiErr.StatusCode != http.StatusBadRequest {
		return false
	}
	return exactInSpaceMissingVMPhrase(message, "no such virtual machine exists") ||
		exactInSpaceMissingVMPhrase(message, "no such vm exists")
}

func exactInSpaceMissingVMPhrase(message, phrase string) bool {
	if message == phrase {
		return true
	}
	if !strings.HasPrefix(message, phrase) || len(message) == len(phrase) {
		return false
	}
	// Live responses use ':' before the UUID; the published InSpace API spec
	// uses '.'. Require the entire suffix to be one canonical UUID; accepting
	// arbitrary prose after either separator could turn an authorization or
	// billing error into destructive absence authority.
	if message[len(phrase)] != ':' && message[len(phrase)] != '.' {
		return false
	}
	suffix := strings.TrimSpace(message[len(phrase)+1:])
	return uuidPattern.MatchString(suffix)
}
