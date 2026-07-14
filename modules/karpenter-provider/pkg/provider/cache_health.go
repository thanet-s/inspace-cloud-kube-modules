package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

const cacheHealthProbeTimeout = 10 * time.Second

// CacheHealthProber gates billable VM creation on the private bootstrap cache.
// Implementations must validate TLS for the deterministic cache hostname while
// connecting directly to the bastion VM's allocator-assigned private IPv4.
type CacheHealthProber interface {
	Probe(ctx context.Context, healthURL, address, caBundle string) error
}

// HTTPSCacheHealthProber uses only the NodeClass CA bundle, bypasses proxy
// environment variables, refuses redirects, and dials the pinned private IPv4.
type HTTPSCacheHealthProber struct{}

func (HTTPSCacheHealthProber) Probe(ctx context.Context, healthURL, address, caBundle string) error {
	endpoint, err := url.Parse(healthURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Path != "/healthz" || endpoint.RawPath != "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Port() != fmt.Sprint(inspacev1.BootstrapCachePort) {
		return fmt.Errorf("health URL must be canonical private HTTPS /healthz on port %d", inspacev1.BootstrapCachePort)
	}
	cacheAddress, err := netip.ParseAddr(address)
	if err != nil || !cacheAddress.Is4() || !cacheAddress.IsPrivate() || cacheAddress.String() != address {
		return fmt.Errorf("address must be a canonical RFC1918 IPv4")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caBundle)) {
		return fmt.Errorf("CA bundle contains no parseable certificates")
	}

	probeCtx, cancel := context.WithTimeout(ctx, cacheHealthProbeTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	dialAddress := net.JoinHostPort(cacheAddress.String(), fmt.Sprint(inspacev1.BootstrapCachePort))
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != endpoint.Host {
				return nil, fmt.Errorf("refusing unexpected cache dial target %q", address)
			}
			return dialer.DialContext(ctx, network, dialAddress)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: endpoint.Hostname(),
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("GET %s via %s: %w", endpoint.String(), dialAddress, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned %s", endpoint.String(), response.Status)
	}
	return nil
}
