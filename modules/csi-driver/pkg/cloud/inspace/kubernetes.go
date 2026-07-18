package inspace

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const serviceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

var nodeNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)

var errKubernetesNodeNotFound = errors.New("Kubernetes node not found")

// KubernetesNodeResolver performs Node provider-ID reads and persists CSI
// cloud-mutation fences as coordination.k8s.io Leases without pulling the full
// client-go dependency graph. It uses the rotating projected ServiceAccount
// token on every request.
type KubernetesNodeResolver struct {
	baseURL   *url.URL
	client    *http.Client
	tokenPath string
	namespace string
}

type KubernetesResolverConfig struct {
	BaseURL       string
	CAFile        string
	TokenFile     string
	Namespace     string
	NamespaceFile string
	Timeout       time.Duration
}

func NewInClusterNodeResolver() (*KubernetesNodeResolver, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	host = strings.Trim(host, "[]")
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes service environment is not configured")
	}
	return NewKubernetesNodeResolver(KubernetesResolverConfig{
		BaseURL:       "https://" + net.JoinHostPort(host, port),
		CAFile:        filepath.Join(serviceAccountPath, "ca.crt"),
		TokenFile:     filepath.Join(serviceAccountPath, "token"),
		NamespaceFile: filepath.Join(serviceAccountPath, "namespace"),
		Timeout:       15 * time.Second,
	})
}

func NewKubernetesNodeResolver(cfg KubernetesResolverConfig) (*KubernetesNodeResolver, error) {
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("Kubernetes API base URL must be an absolute HTTPS URL")
	}
	if cfg.CAFile == "" || cfg.TokenFile == "" {
		return nil, errors.New("Kubernetes CA and ServiceAccount token files are required")
	}
	namespace := strings.TrimSpace(cfg.Namespace)
	if namespace == "" && cfg.NamespaceFile != "" {
		value, err := os.ReadFile(cfg.NamespaceFile)
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes ServiceAccount namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(value))
	}
	if namespace == "" {
		namespace = "default"
	}
	if !nodeNamePattern.MatchString(namespace) {
		return nil, errors.New("invalid Kubernetes namespace")
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Kubernetes CA file contains no certificates")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Kubernetes API redirects are disabled")
		},
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &KubernetesNodeResolver{baseURL: baseURL, client: client, tokenPath: cfg.TokenFile, namespace: namespace}, nil
}

func (r *KubernetesNodeResolver) ProviderIDForNode(ctx context.Context, nodeName string) (string, error) {
	if !nodeNamePattern.MatchString(nodeName) {
		return "", errors.New("invalid Kubernetes node name")
	}
	token, err := os.ReadFile(r.tokenPath)
	if err != nil {
		return "", fmt.Errorf("%w: read Kubernetes ServiceAccount token: %v", cloud.ErrUnavailable, err)
	}
	u := *r.baseURL
	u.Path = strings.TrimRight(r.baseURL.Path, "/") + "/api/v1/nodes/" + url.PathEscape(nodeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", fmt.Errorf("%w: query Kubernetes node: %v", cloud.ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", fmt.Errorf("%w: read Kubernetes node: %v", cloud.ErrUnavailable, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("%w: %q", errKubernetesNodeNotFound, nodeName)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return "", fmt.Errorf("%w: Kubernetes API returned HTTP %d", cloud.ErrUnavailable, resp.StatusCode)
		}
		return "", fmt.Errorf("Kubernetes API returned HTTP %d", resp.StatusCode)
	}
	var node struct {
		Spec struct {
			ProviderID string `json:"providerID"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &node); err != nil {
		return "", fmt.Errorf("%w: decode Kubernetes node: %v", cloud.ErrUnavailable, err)
	}
	if strings.TrimSpace(node.Spec.ProviderID) == "" {
		return "", fmt.Errorf("Kubernetes node %q has no spec.providerID", nodeName)
	}
	return node.Spec.ProviderID, nil
}

var _ NodeResolver = (*KubernetesNodeResolver)(nil)
