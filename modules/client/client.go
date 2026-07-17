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
	defaultUserAgent           = "cloud-provider-inspace/dev"
	defaultHTTPTimeout         = 5 * time.Minute
	defaultReadTimeout         = 30 * time.Second
	maxResponseBodyBytes       = 4 << 20
	warrenCorrelationIDHeader  = "X-Warren-Correlation-Id"
	maxWarrenCorrelationIDSize = 128
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
	// ErrReadRedirect prevents an exact or collection read from silently
	// changing endpoint identity. Controllers use successful GETs as
	// authoritative presence/absence evidence, so even a same-origin redirect
	// must be handled as an error rather than rebound to the original request.
	ErrReadRedirect            = errors.New("inspace: read redirect blocked")
	locationPattern            = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern                = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	warrenCorrelationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
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
	httpClientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) != 0 && isMutation(via[len(via)-1].Method) {
			return fmt.Errorf("%w: %s to %s", ErrMutationRedirect, via[len(via)-1].Method, req.URL.Redacted())
		}
		if !sameOrigin(baseURL, req.URL) {
			return fmt.Errorf("%w: %s", ErrCrossOriginRedirect, req.URL.Redacted())
		}
		if len(via) != 0 {
			return fmt.Errorf("%w: %s to %s", ErrReadRedirect, via[len(via)-1].Method, req.URL.Redacted())
		}
		return errors.New("inspace: redirect blocked")
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

func validateResponseUUID(kind, value string) error {
	if err := validateUUID(kind, value); err != nil {
		return fmt.Errorf("inspace: malformed %s response identity: %w", kind, err)
	}
	return nil
}

func validateExpectedResponseUUID(kind, value, expected string) error {
	if err := validateResponseUUID(kind, value); err != nil {
		return err
	}
	if !strings.EqualFold(value, expected) {
		return fmt.Errorf("inspace: %s response UUID %q does not match expected UUID %q", kind, value, expected)
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
		// net/http can return both a response and an error when redirect policy
		// rejects the response. Preserve the provider-generated diagnostic
		// correlation ID without weakening the no-redirect mutation contract.
		if resp != nil {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return &APIError{
				StatusCode:    resp.StatusCode,
				Method:        method,
				Path:          path,
				Message:       err.Error(),
				Retryable:     retryableAPIStatus(resp.StatusCode),
				CorrelationID: validatedWarrenCorrelationID(resp.Header),
				cause:         err,
			}
		}
		return fmt.Errorf("inspace: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	correlationID := validatedWarrenCorrelationID(resp.Header)
	if resp.ContentLength > maxResponseBodyBytes {
		return newIncompleteAPIError(
			method,
			path,
			resp.StatusCode,
			fmt.Sprintf("declared response body exceeds %d bytes and was not trusted", maxResponseBodyBytes),
			correlationID,
			nil,
		)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return newIncompleteAPIError(
			method,
			path,
			resp.StatusCode,
			fmt.Sprintf("response body could not be read completely: %v", err),
			correlationID,
			err,
		)
	}
	if len(data) > maxResponseBodyBytes {
		return newIncompleteAPIError(
			method,
			path,
			resp.StatusCode,
			fmt.Sprintf("response body exceeds %d bytes and was not trusted", maxResponseBodyBytes),
			correlationID,
			nil,
		)
	}
	if resp.ContentLength > 0 && int64(len(data)) != resp.ContentLength {
		return newIncompleteAPIError(
			method,
			path,
			resp.StatusCode,
			fmt.Sprintf("response body length %d does not match declared length %d", len(data), resp.ContentLength),
			correlationID,
			nil,
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(method, path, resp.StatusCode, data, correlationID)
	}
	if err := validateSuccessResponse(method, path, resp.StatusCode, out != nil, data, correlationID); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return newMalformedResponseAPIError(method, path, resp.StatusCode, "expected a non-empty JSON value", correlationID, nil)
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return newMalformedResponseAPIError(method, path, resp.StatusCode, "expected a non-null JSON value", correlationID, nil)
	}
	if err := validateJSONNoDuplicateObjectKeys(trimmed); err != nil {
		return newMalformedResponseAPIError(method, path, resp.StatusCode, err.Error(), correlationID, err)
	}
	if trimmed[0] == '{' {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err == nil && len(object) == 0 {
			return newMalformedResponseAPIError(method, path, resp.StatusCode, "expected a non-empty JSON object", correlationID, nil)
		}
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		return newMalformedResponseAPIError(method, path, resp.StatusCode, err.Error(), correlationID, err)
	}
	return nil
}

// validateJSONNoDuplicateObjectKeys rejects ambiguous JSON before it reaches
// encoding/json, whose default last-key-wins behavior could otherwise replace
// an identity or relationship field. It also proves that the input contains
// exactly one complete JSON value.
func validateJSONNoDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("invalid trailing JSON: %w", err)
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON object: %w", err)
		}
		if end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON array: %w", err)
		}
		if end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

type successBodyContract uint8

const (
	successJSON successBodyContract = iota
	successEmpty
	successEmptyOrJSON
)

type endpointContract struct {
	method       string
	pathTemplate string
	statuses     []int
	body         successBodyContract
}

var (
	statusOKOnly        = []int{http.StatusOK}
	statusCreatedOnly   = []int{http.StatusCreated}
	statusOKOrCreated   = []int{http.StatusOK, http.StatusCreated}
	statusNoContentOnly = []int{http.StatusNoContent}
	statusOKOrNoContent = []int{http.StatusOK, http.StatusNoContent}
)

// endpointContracts is deliberately an exhaustive whitelist of every route
// used by this SDK. InSpace does not use one generic status convention:
// notably, disk/firewall deletes return 204 while floating-IP and NLB deletes
// return an empty 200 response. A method-wide default would therefore either
// reject a documented success or accept an ambiguous response.
var endpointContracts = []endpointContract{
	{http.MethodGet, "/v1/config/locations", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/config/vm_images", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/user-resource/host_pool/list", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/user-resource/vm/list", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/user-resource/vm", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/storage/disks", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/storage/disks/{uuid}", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/ip_addresses", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/ip_addresses/{address}", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/firewalls", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/load_balancers", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/load_balancers/{uuid}", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/network/{uuid}", statusOKOnly, successJSON},
	{http.MethodGet, "/v1/{location}/network/networks", statusOKOnly, successJSON},

	{http.MethodPost, "/v1/{location}/user-resource/vm", statusCreatedOnly, successJSON},
	{http.MethodPost, "/v1/{location}/storage/disks", statusCreatedOnly, successJSON},
	// The live floating-IP API has returned 200 with the created object, while
	// the existing SDK contract accepts conventional 201 responses. Both
	// statuses carry the same required JSON object contract.
	{http.MethodPost, "/v1/{location}/network/ip_addresses", statusOKOrCreated, successJSON},
	{http.MethodPost, "/v1/{location}/network/firewalls", statusCreatedOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/load_balancers", statusCreatedOnly, successJSON},

	{http.MethodPost, "/v1/{location}/user-resource/vm/storage/attach", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/user-resource/vm/storage/detach", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/ip_addresses/{address}/assign", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/ip_addresses/{address}/unassign", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/firewalls/{uuid}/vms", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/load_balancers/{uuid}/targets", statusOKOnly, successJSON},
	{http.MethodPost, "/v1/{location}/network/load_balancers/{uuid}/forwarding_rules", statusOKOnly, successJSON},
	{http.MethodPut, "/v1/{location}/network/firewalls/{uuid}", statusOKOnly, successJSON},
	{http.MethodPatch, "/v1/{location}/network/ip_addresses/{address}", statusOKOnly, successJSON},

	// The VM API reference does not state a success response. The live API can
	// return either an empty 204 or a JSON-bearing 200. The body is never used
	// as deletion proof: every production caller performs authoritative exact
	// absence readback after dispatch.
	{http.MethodDelete, "/v1/{location}/user-resource/vm", statusOKOrNoContent, successEmptyOrJSON},
	{http.MethodDelete, "/v1/{location}/storage/disks/{uuid}", statusNoContentOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/ip_addresses/{address}", statusOKOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/firewalls/{uuid}", statusNoContentOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/firewalls/{uuid}/vms", statusNoContentOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/load_balancers/{uuid}", statusOKOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/load_balancers/{uuid}/targets/{uuid}", statusOKOnly, successEmpty},
	{http.MethodDelete, "/v1/{location}/network/load_balancers/{uuid}/forwarding_rules/{uuid}", statusOKOnly, successEmpty},
}

func validateSuccessResponse(method, path string, status int, expectsJSON bool, data []byte, correlationID string) error {
	contract, ok := endpointSuccessContract(method, path)
	if !ok {
		return &APIError{
			StatusCode:    status,
			Method:        method,
			Path:          path,
			Message:       "successful response has no registered SDK endpoint contract",
			CorrelationID: correlationID,
		}
	}
	if !containsHTTPStatus(contract.statuses, status) {
		return &APIError{
			StatusCode:    status,
			Method:        method,
			Path:          path,
			Message:       fmt.Sprintf("unexpected successful HTTP status %d for this endpoint; allowed statuses are %v", status, contract.statuses),
			CorrelationID: correlationID,
		}
	}
	if expectsJSON != (contract.body == successJSON) {
		return &APIError{
			StatusCode:    status,
			Method:        method,
			Path:          path,
			Message:       fmt.Sprintf("internal response contract mismatch: JSON output=%t", expectsJSON),
			CorrelationID: correlationID,
		}
	}
	trimmed := bytes.TrimSpace(data)
	switch contract.body {
	case successEmpty:
		if len(trimmed) != 0 {
			return newMalformedResponseAPIError(
				method,
				path,
				status,
				"expected an empty success body",
				correlationID,
				nil,
			)
		}
	case successEmptyOrJSON:
		if len(trimmed) != 0 {
			if err := validateJSONNoDuplicateObjectKeys(trimmed); err != nil {
				return newMalformedResponseAPIError(
					method,
					path,
					status,
					fmt.Sprintf("invalid optional success response: %v", err),
					correlationID,
					err,
				)
			}
		}
	}
	return nil
}

func validWarrenCorrelationID(value string) bool {
	return value != "" &&
		len(value) <= maxWarrenCorrelationIDSize &&
		warrenCorrelationIDPattern.MatchString(value)
}

// validatedWarrenCorrelationID accepts exactly one compact ASCII identifier.
// The header is provider-generated diagnostic metadata, never dispatch or
// idempotency authority. Ambiguous, oversized, or log-unsafe values are
// discarded instead of being reflected into controller logs.
func validatedWarrenCorrelationID(header http.Header) string {
	values := header.Values(warrenCorrelationIDHeader)
	if len(values) != 1 || !validWarrenCorrelationID(values[0]) {
		return ""
	}
	return values[0]
}

func newMalformedResponseAPIError(
	method, path string,
	status int,
	message, correlationID string,
	cause error,
) *APIError {
	return &APIError{
		StatusCode:            status,
		Method:                method,
		Path:                  path,
		Message:               message,
		Retryable:             retryableHTTPResponseFailure(status, cause),
		CorrelationID:         correlationID,
		ResponseBodyMalformed: true,
		cause:                 cause,
	}
}

func newIncompleteAPIError(
	method, path string,
	status int,
	message, correlationID string,
	cause error,
) *APIError {
	return &APIError{
		StatusCode:             status,
		Method:                 method,
		Path:                   path,
		Message:                message,
		Retryable:              retryableHTTPResponseFailure(status, cause),
		CorrelationID:          correlationID,
		ResponseBodyIncomplete: true,
		cause:                  cause,
	}
}

func containsHTTPStatus(statuses []int, candidate int) bool {
	for _, status := range statuses {
		if status == candidate {
			return true
		}
	}
	return false
}

func endpointSuccessContract(method, path string) (endpointContract, bool) {
	for _, contract := range endpointContracts {
		if contract.method == method && endpointPathMatches(path, contract.pathTemplate) {
			return contract, true
		}
	}
	return endpointContract{}, false
}

func endpointPathMatches(path, template string) bool {
	pathParts := strings.Split(path, "/")
	templateParts := strings.Split(template, "/")
	if len(pathParts) != len(templateParts) {
		return false
	}
	for index := range templateParts {
		switch templateParts[index] {
		case "{location}":
			if !locationPattern.MatchString(pathParts[index]) {
				return false
			}
		case "{uuid}":
			if !uuidPattern.MatchString(pathParts[index]) {
				return false
			}
		case "{address}":
			if net.ParseIP(pathParts[index]) == nil {
				return false
			}
		default:
			if pathParts[index] != templateParts[index] {
				return false
			}
		}
	}
	return true
}

// validatedListResponse distinguishes a valid empty JSON array from a
// successful response whose body was empty or JSON null. It also requires
// every row to expose one valid, unique canonical identity. A nil collection
// or malformed row must never become authoritative absence evidence in a
// controller.
func validatedListResponse[T any](
	result []T,
	err error,
	method, path string,
	identity func(T) (string, error),
) ([]T, error) {
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, fmt.Errorf("inspace: decode %s %s response: expected a JSON array, got an empty or null body", method, path)
	}
	seen := make(map[string]int, len(result))
	for index, item := range result {
		key, identityErr := identity(item)
		if identityErr != nil {
			return nil, fmt.Errorf("inspace: decode %s %s response: invalid list element %d identity: %w", method, path, index, identityErr)
		}
		if key == "" {
			return nil, fmt.Errorf("inspace: decode %s %s response: invalid list element %d identity: empty canonical key", method, path, index)
		}
		if previous, ok := seen[key]; ok {
			return nil, fmt.Errorf("inspace: decode %s %s response: duplicate canonical identity %q at list elements %d and %d", method, path, key, previous, index)
		}
		seen[key] = index
	}
	return result, nil
}

func validatedUUIDListIdentity(kind, value string) (string, error) {
	if err := validateUUID(kind, value); err != nil {
		return "", err
	}
	return strings.ToLower(value), nil
}

func validatedRequiredListIdentity(kind, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("inspace: empty %s", kind)
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("inspace: invalid %s %q", kind, value)
	}
	return strings.ToLower(value), nil
}

// APIError is a normalized HTTP response failure. It covers non-2xx responses
// as well as malformed, incomplete, or endpoint-incompatible successful
// responses. Retryable is only a scheduling hint: for POST, PUT, PATCH, and
// DELETE, no HTTP status proves that the mutation did not commit. Callers must
// resolve the outcome by authoritative readback before replaying or releasing
// durable ownership.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Message    string
	Retryable  bool
	// CorrelationID is provider-generated diagnostic metadata from the
	// X-Warren-Correlation-Id response header. It is strictly validated before
	// storage and must never be used as mutation or idempotency authority.
	CorrelationID string
	// ResponseBodyIncomplete is true when response headers were observed but
	// the error body could not be read in full. Status still provides a retry
	// scheduling hint, but an incomplete 400/404 body must never become
	// authoritative resource absence.
	ResponseBodyIncomplete bool
	// ResponseBodyMalformed is true when a response claims a structured JSON
	// error body but that body is malformed or contains duplicate object keys.
	// Such a body can never supply semantic not-found authority.
	ResponseBodyMalformed bool
	// ExactLookup is set only by a resource-specific SDK lookup after binding
	// the response to its requested canonical UUID. Generic route/list errors,
	// including HTTP 404, are never authoritative resource absence.
	ExactLookup bool
	// RequestedUUID is populated only when a caller can bind the error to one
	// exact resource lookup. Generic HTTP plumbing deliberately leaves it
	// empty because many endpoints carry no singular resource identity.
	RequestedUUID string
	// RequestedAddress is populated only by an exact floating-IP lookup.
	// Floating IP identity is its canonical public address, not a UUID.
	RequestedAddress string
	cause            error
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("inspace: %s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
	switch {
	case e.CorrelationID == "":
		return message
	case validWarrenCorrelationID(e.CorrelationID):
		return fmt.Sprintf("%s [correlation-id=%s]", message, e.CorrelationID)
	default:
		// APIError is exported and callers can construct it directly. Keep
		// Error() log-safe even when a caller bypasses constructor validation.
		return message + " [correlation-id=<redacted>]"
	}
}

func (e *APIError) Unwrap() error {
	return e.cause
}

func newAPIError(method, path string, status int, data []byte, correlationID string) *APIError {
	message := strings.TrimSpace(string(data))
	var payload struct {
		Error   any            `json:"error"`
		Message string         `json:"message"`
		Errors  map[string]any `json:"errors"`
	}
	malformed := false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) != 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		malformed = validateJSONNoDuplicateObjectKeys(trimmed) != nil
	}
	if !malformed && json.Unmarshal(data, &payload) == nil {
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
		StatusCode:            status,
		Method:                method,
		Path:                  path,
		Message:               message,
		Retryable:             retryableAPIStatus(status),
		CorrelationID:         correlationID,
		ResponseBodyMalformed: malformed,
	}
}

func retryableAPIStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests ||
		status >= 500
}

func retryableHTTPResponseFailure(status int, cause error) bool {
	if retryableAPIStatus(status) {
		return true
	}
	var networkErr net.Error
	return errors.As(cause, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func bindExactLookupError(err error, requestedUUID string) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	bound := *apiErr
	bound.ExactLookup = true
	bound.RequestedUUID = requestedUUID
	return &bound
}

func bindExactFloatingIPLookupError(err error, requestedAddress string) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	bound := *apiErr
	bound.ExactLookup = true
	bound.RequestedAddress = requestedAddress
	return &bound
}

// IsNotFound reports whether err represents an absent resource. InSpace uses
// HTTP 400 with a "No such virtual machine exists" message (sometimes followed
// by the UUID) for some already-deleted exact VM lookups, so that narrowly
// bound semantic response is normalized alongside HTTP 404. Other "No such
// ... exists" errors can describe billing, network, or authorization state and
// must remain ordinary failures.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.ResponseBodyIncomplete || apiErr.ResponseBodyMalformed {
		return false
	}
	if apiErr.StatusCode == http.StatusNotFound {
		if !apiErr.ExactLookup || apiErr.Method != http.MethodGet {
			return false
		}
		if apiErr.RequestedAddress != "" {
			return apiErr.RequestedUUID == "" &&
				isPublicIPv4(apiErr.RequestedAddress) &&
				isExactFloatingIPPath(apiErr.Path, apiErr.RequestedAddress)
		}
		return uuidPattern.MatchString(apiErr.RequestedUUID) &&
			isBoundExactLookupPath(apiErr.Path, apiErr.RequestedUUID)
	}
	if apiErr.StatusCode != http.StatusBadRequest ||
		!apiErr.ExactLookup ||
		apiErr.Method != http.MethodGet ||
		!isExactVMDetailPath(apiErr.Path) ||
		!uuidPattern.MatchString(apiErr.RequestedUUID) {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(apiErr.Message))
	message = strings.TrimSpace(strings.TrimPrefix(message, "error:"))
	messageUUID, ok := exactInSpaceMissingVMUUID(message, "no such virtual machine exists")
	if !ok {
		messageUUID, ok = exactInSpaceMissingVMUUID(message, "no such vm exists")
	}
	return ok && (messageUUID == "" || strings.EqualFold(messageUUID, apiErr.RequestedUUID))
}

func isPublicIPv4(value string) bool {
	address := net.ParseIP(value)
	return address != nil &&
		address.To4() != nil &&
		address.IsGlobalUnicast() &&
		!address.IsPrivate() &&
		!address.IsLoopback() &&
		!address.IsUnspecified() &&
		address.String() == value
}

func isExactFloatingIPPath(path, requestedAddress string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 6 &&
		parts[0] == "" &&
		parts[1] == "v1" &&
		locationPattern.MatchString(parts[2]) &&
		parts[3] == "network" &&
		parts[4] == "ip_addresses" &&
		parts[5] == requestedAddress
}

func isBoundExactLookupPath(path, requestedUUID string) bool {
	if isExactVMDetailPath(path) {
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 6 &&
		parts[0] == "" &&
		parts[1] == "v1" &&
		locationPattern.MatchString(parts[2]) &&
		strings.EqualFold(parts[5], requestedUUID) {
		return (parts[3] == "storage" && parts[4] == "disks") ||
			(parts[3] == "network" && parts[4] == "network") ||
			(parts[3] == "network" && parts[4] == "load_balancers")
	}
	return false
}

func exactInSpaceMissingVMUUID(message, phrase string) (string, bool) {
	if message == phrase {
		return "", true
	}
	if !strings.HasPrefix(message, phrase) {
		return "", false
	}
	// Live responses use ':' before the UUID; the published InSpace API spec
	// uses '.'. Require the entire suffix to be one canonical UUID; accepting
	// arbitrary prose after either separator could turn an authorization or
	// billing error into destructive absence authority.
	if message[len(phrase)] != ':' && message[len(phrase)] != '.' {
		return "", false
	}
	suffix := strings.TrimSpace(message[len(phrase)+1:])
	return suffix, uuidPattern.MatchString(suffix)
}

func isExactVMDetailPath(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 5 &&
		parts[0] == "" &&
		parts[1] == "v1" &&
		locationPattern.MatchString(parts[2]) &&
		parts[3] == "user-resource" &&
		parts[4] == "vm"
}
