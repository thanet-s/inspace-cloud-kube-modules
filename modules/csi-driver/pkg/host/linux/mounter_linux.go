//go:build linux

// Package linux implements the privileged node-side CSI mount operations.
package linux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host"
)

const mountInfoPath = "/proc/self/mountinfo"

type Mounter struct {
	devicePollInterval time.Duration
}

func New() (host.Mounter, error) {
	m := &Mounter{devicePollInterval: 250 * time.Millisecond}
	if err := m.Probe(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Mounter) Probe(context.Context) error {
	for _, command := range []string{"blkid", "mkfs.ext4", "mount", "umount"} {
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("required host command %q is unavailable: %w", command, err)
		}
	}
	file, err := os.Open(mountInfoPath)
	if err != nil {
		return fmt.Errorf("open mountinfo: %w", err)
	}
	return file.Close()
}

func (m *Mounter) WaitForDevice(ctx context.Context, devicePath string) (string, error) {
	if err := validateAbsolutePath(devicePath); err != nil {
		return "", err
	}
	interval := m.devicePollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		resolved, err := filepath.EvalSymlinks(devicePath)
		if err == nil {
			info, statErr := os.Stat(resolved)
			if statErr == nil && info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
				return resolved, nil
			}
			if statErr != nil && !os.IsNotExist(statErr) {
				return "", fmt.Errorf("stat device %q: %w", resolved, statErr)
			}
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolve device %q: %w", devicePath, err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Mounter) GetMount(ctx context.Context, target string) (host.Mount, bool, error) {
	if err := ctx.Err(); err != nil {
		return host.Mount{}, false, err
	}
	if err := validateAbsolutePath(target); err != nil {
		return host.Mount{}, false, err
	}
	file, err := os.Open(mountInfoPath)
	if err != nil {
		return host.Mount{}, false, fmt.Errorf("open mountinfo: %w", err)
	}
	defer file.Close()
	cleanTarget := filepath.Clean(target)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		left, right, ok := strings.Cut(scanner.Text(), " - ")
		if !ok {
			continue
		}
		leftFields := strings.Fields(left)
		rightFields := strings.Fields(right)
		if len(leftFields) < 6 || len(rightFields) < 3 {
			continue
		}
		mountTarget := unescapeMountInfo(leftFields[4])
		if filepath.Clean(mountTarget) != cleanTarget {
			continue
		}
		options := strings.Split(leftFields[5], ",")
		superOptions := strings.Split(rightFields[2], ",")
		readOnly := slices.Contains(options, "ro") || slices.Contains(superOptions, "ro")
		source := unescapeMountInfo(rightFields[1])
		if resolved, resolveErr := filepath.EvalSymlinks(source); resolveErr == nil {
			source = resolved
		}
		return host.Mount{
			Source: source, Target: mountTarget, FSType: rightFields[0], ReadOnly: readOnly,
			MountFlags: slices.Clone(options),
		}, true, nil
	}
	if err := scanner.Err(); err != nil {
		return host.Mount{}, false, fmt.Errorf("read mountinfo: %w", err)
	}
	return host.Mount{}, false, nil
}

func (m *Mounter) SameSource(ctx context.Context, mounted host.Mount, expectedSource string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := validateAbsolutePath(expectedSource); err != nil {
		return false, err
	}
	expectedInfo, err := os.Stat(expectedSource)
	if err != nil {
		return false, fmt.Errorf("stat expected mount source: %w", err)
	}
	if expectedInfo.IsDir() {
		targetInfo, err := os.Stat(mounted.Target)
		if err != nil {
			return false, fmt.Errorf("stat mount target: %w", err)
		}
		return os.SameFile(expectedInfo, targetInfo), nil
	}
	actualInfo, err := os.Stat(mounted.Source)
	if err != nil {
		return false, fmt.Errorf("stat mounted source: %w", err)
	}
	return os.SameFile(expectedInfo, actualInfo), nil
}

func (m *Mounter) FormatAndMount(ctx context.Context, devicePath, target, fsType string, mountFlags []string) error {
	if fsType != "ext4" {
		return fmt.Errorf("only ext4 is supported, got %q", fsType)
	}
	if err := validateAbsolutePath(devicePath); err != nil {
		return err
	}
	if err := validateAbsolutePath(target); err != nil {
		return err
	}
	flags, err := validateFlags(mountFlags, false)
	if err != nil {
		return err
	}
	if mounted, present, err := m.GetMount(ctx, target); err != nil {
		return err
	} else if present {
		matches, compareErr := m.SameSource(ctx, mounted, devicePath)
		if compareErr != nil {
			return compareErr
		}
		if matches && mounted.FSType == "ext4" && !mounted.ReadOnly {
			return nil
		}
		return fmt.Errorf("%w: %s", host.ErrMountConflict, target)
	}
	filesystem, err := probeFilesystem(ctx, devicePath)
	if err != nil {
		return err
	}
	switch filesystem {
	case "":
		if _, err := run(ctx, "mkfs.ext4", "-F", "-m", "0", devicePath); err != nil {
			return fmt.Errorf("format ext4 device: %w", err)
		}
	case "ext4":
	default:
		return fmt.Errorf("%w: device contains %s, expected ext4", host.ErrMountConflict, filesystem)
	}
	if err := os.MkdirAll(target, 0o750); err != nil {
		return fmt.Errorf("create staging target: %w", err)
	}
	args := []string{"-t", "ext4"}
	if len(flags) != 0 {
		args = append(args, "-o", strings.Join(flags, ","))
	}
	args = append(args, "--", devicePath, target)
	if _, err := run(ctx, "mount", args...); err != nil {
		return fmt.Errorf("mount ext4 device: %w", err)
	}
	return nil
}

func (m *Mounter) BindMount(ctx context.Context, source, target string, readOnly bool, mountFlags []string) error {
	if err := validateAbsolutePath(source); err != nil {
		return err
	}
	if err := validateAbsolutePath(target); err != nil {
		return err
	}
	flags, err := validateFlags(mountFlags, true)
	if err != nil {
		return err
	}
	if _, present, err := m.GetMount(ctx, source); err != nil {
		return err
	} else if !present {
		return fmt.Errorf("bind source is not a mount point: %s", source)
	}
	if mounted, present, err := m.GetMount(ctx, target); err != nil {
		return err
	} else if present {
		matches, compareErr := m.SameSource(ctx, mounted, source)
		if compareErr != nil {
			return compareErr
		}
		if matches && mounted.ReadOnly == readOnly {
			return nil
		}
		return fmt.Errorf("%w: %s", host.ErrMountConflict, target)
	}
	if err := os.MkdirAll(target, 0o750); err != nil {
		return fmt.Errorf("create publish target: %w", err)
	}
	if _, err := run(ctx, "mount", "--bind", "--", source, target); err != nil {
		return fmt.Errorf("bind mount: %w", err)
	}
	if readOnly || len(flags) != 0 {
		options := []string{"remount", "bind"}
		if readOnly {
			options = append(options, "ro")
		} else {
			options = append(options, "rw")
		}
		options = append(options, flags...)
		if _, err := run(ctx, "mount", "-o", strings.Join(options, ","), "--", target); err != nil {
			_, _ = run(context.Background(), "umount", "--", target)
			return fmt.Errorf("apply bind mount options: %w", err)
		}
	}
	return nil
}

func (m *Mounter) Unmount(ctx context.Context, target string) error {
	if err := validateAbsolutePath(target); err != nil {
		return err
	}
	if _, present, err := m.GetMount(ctx, target); err != nil {
		return err
	} else if !present {
		_ = os.Remove(target)
		return nil
	}
	if _, err := run(ctx, "umount", "--", target); err != nil {
		return fmt.Errorf("unmount target: %w", err)
	}
	_ = os.Remove(target)
	return nil
}

func probeFilesystem(ctx context.Context, device string) (string, error) {
	output, err := run(ctx, "blkid", "-p", "-s", "TYPE", "-o", "value", device)
	if err == nil {
		return strings.TrimSpace(output), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 && strings.TrimSpace(output) == "" {
		return "", nil
	}
	return "", fmt.Errorf("inspect filesystem: %w", err)
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return string(output), fmt.Errorf("%w: %s", err, message)
		}
	}
	return string(output), err
}

func validateFlags(flags []string, bind bool) ([]string, error) {
	allowed := map[string]bool{
		"discard": true, "noatime": true, "nodiratime": true,
		"nodev": true, "nosuid": true, "noexec": true,
	}
	if !bind {
		allowed["errors=remount-ro"] = true
		allowed["lazytime"] = true
	}
	validated := make([]string, 0, len(flags))
	for _, flag := range flags {
		flag = strings.TrimSpace(flag)
		if flag == "" || strings.ContainsAny(flag, ", \t\r\n") || !allowed[flag] {
			return nil, fmt.Errorf("unsupported mount flag %q", flag)
		}
		if !slices.Contains(validated, flag) {
			validated = append(validated, flag)
		}
	}
	return validated, nil
}

func validateAbsolutePath(value string) error {
	if value == "" || strings.ContainsRune(value, '\x00') || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("path must be a clean absolute path: %q", value)
	}
	return nil
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

var _ host.Mounter = (*Mounter)(nil)
