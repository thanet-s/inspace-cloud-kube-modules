package inspace_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestIsTransientClassifiesProviderErrors(t *testing.T) {
	vm := "11111111-1111-4111-8111-111111111111"
	status := func(code int, retryable bool) *inspace.APIError {
		return &inspace.APIError{StatusCode: code, Method: http.MethodGet, Path: "/v1/vm", Retryable: retryable}
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "503", err: status(http.StatusServiceUnavailable, true), want: true},
		{name: "502", err: status(http.StatusBadGateway, true), want: true},
		{name: "429", err: status(http.StatusTooManyRequests, true), want: true},
		{name: "408", err: status(http.StatusRequestTimeout, true), want: true},
		{name: "incomplete body", err: &inspace.APIError{StatusCode: http.StatusBadRequest, ResponseBodyIncomplete: true}, want: true},
		{name: "wrapped 503", err: fmt.Errorf("read canonical VM: %w", status(http.StatusServiceUnavailable, true)), want: true},
		{name: "403", err: status(http.StatusForbidden, false), want: false},
		{name: "plain 404", err: status(http.StatusNotFound, false), want: false},
		{
			name: "exact GET 404",
			err: &inspace.APIError{
				StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/vm/" + vm,
				ExactLookup: true, RequestedUUID: vm,
			},
			want: false,
		},
		{name: "malformed 200 body", err: &inspace.APIError{StatusCode: http.StatusOK, ResponseBodyMalformed: true}, want: false},
		{name: "mutation not dispatched", err: fmt.Errorf("%w: %w", inspace.ErrMutationNotDispatched, context.Canceled), want: false},
		{name: "url timeout", err: fmt.Errorf("inspace: GET /v1/vm: %w", &url.Error{Op: "Get", URL: "https://x", Err: timeoutNetError{}}), want: true},
		{name: "wrapped deadline", err: fmt.Errorf("read canonical VM: %w", context.DeadlineExceeded), want: true},
		{name: "canceled", err: fmt.Errorf("sync: %w", context.Canceled), want: true},
		{name: "url refused", err: &url.Error{Op: "Get", URL: "https://x", Err: errors.New("connection refused")}, want: true},
		{name: "wrapped url error with syscall refused", err: fmt.Errorf("inspace: GET /v1/vm: %w", &url.Error{Op: "Get", URL: "https://x", Err: syscall.ECONNREFUSED}), want: true},
		{name: "ECONNREFUSED", err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED), want: true},
		{name: "ECONNRESET", err: fmt.Errorf("read: %w", syscall.ECONNRESET), want: true},
		{name: "EPIPE", err: fmt.Errorf("write: %w", syscall.EPIPE), want: true},
		{name: "ETIMEDOUT", err: fmt.Errorf("dial: %w", syscall.ETIMEDOUT), want: true},
		{name: "EHOSTUNREACH", err: fmt.Errorf("dial: %w", syscall.EHOSTUNREACH), want: true},
		{name: "ENETUNREACH", err: fmt.Errorf("dial: %w", syscall.ENETUNREACH), want: true},
		{name: "EOF", err: fmt.Errorf("read body: %w", io.EOF), want: true},
		{name: "unexpected EOF", err: fmt.Errorf("read body: %w", io.ErrUnexpectedEOF), want: true},
		{name: "url EOF", err: &url.Error{Op: "Get", URL: "https://x", Err: io.EOF}, want: true},
		{name: "DNS failure", err: fmt.Errorf("inspace: GET /v1/vm: %w", &url.Error{Op: "Get", URL: "https://x", Err: &net.DNSError{Err: "no such host", Name: "api.inspace.cloud", IsNotFound: true}}), want: true},
		{name: "bare DNS failure", err: &net.DNSError{Err: "server misbehaving", Name: "api.inspace.cloud"}, want: true},
		{name: "refused joined with definite", err: errors.Join(syscall.ECONNREFUSED, errors.New("ownership mismatch")), want: false},
		{name: "plain error", err: errors.New("VM read error"), want: false},
		{name: "join transient only", err: errors.Join(status(http.StatusServiceUnavailable, true), context.DeadlineExceeded), want: true},
		{name: "join transient and definite", err: errors.Join(status(http.StatusServiceUnavailable, true), errors.New("ownership mismatch")), want: false},
		{name: "join transient and 404", err: errors.Join(context.DeadlineExceeded, &inspace.APIError{
			StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/vm/" + vm, ExactLookup: true, RequestedUUID: vm,
		}), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := inspace.IsTransient(test.err); got != test.want {
				t.Fatalf("IsTransient(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
