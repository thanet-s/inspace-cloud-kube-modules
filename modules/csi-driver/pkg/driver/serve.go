package driver

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
)

// Serve runs the CSI services on a Unix domain socket until ctx is canceled.
func (d *Driver) Serve(ctx context.Context, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" || u.Path == "" {
		return fmt.Errorf("endpoint must be unix:///absolute/path: %q", endpoint)
	}
	if !filepath.IsAbs(u.Path) {
		return fmt.Errorf("Unix socket path must be absolute: %q", u.Path)
	}
	if err := os.MkdirAll(filepath.Dir(u.Path), 0o750); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if info, statErr := os.Lstat(u.Path); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket endpoint %q", u.Path)
		}
		if err := os.Remove(u.Path); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect socket: %w", statErr)
	}
	listener, err := net.Listen("unix", u.Path)
	if err != nil {
		return fmt.Errorf("listen on CSI socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(u.Path)
	// Controller sidecars share this socket through the Pod fsGroup. Unix
	// stream clients need write permission on the socket itself to connect.
	if err := os.Chmod(u.Path, 0o660); err != nil {
		return fmt.Errorf("set CSI socket permissions: %w", err)
	}

	server := grpc.NewServer()
	d.Register(server)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.GracefulStop()
		case <-stopped:
		}
	}()
	err = server.Serve(listener)
	close(stopped)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("serve CSI gRPC: %w", err)
	}
	return nil
}
