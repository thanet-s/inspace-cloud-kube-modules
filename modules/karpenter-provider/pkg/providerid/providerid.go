package providerid

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const Scheme = "inspace"

var (
	locationPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

type ID struct {
	Location string
	VMUUID   string
}

func New(location, vmUUID string) string {
	return fmt.Sprintf("%s://%s/%s", Scheme, location, vmUUID)
}

func Parse(value string) (ID, error) {
	u, err := url.Parse(value)
	if err != nil {
		return ID{}, fmt.Errorf("parse provider ID: %w", err)
	}
	vmUUID := strings.TrimPrefix(u.Path, "/")
	if u.Scheme != Scheme || !locationPattern.MatchString(u.Host) || !uuidPattern.MatchString(vmUUID) || strings.Contains(vmUUID, "/") || u.RawQuery != "" || u.Fragment != "" {
		return ID{}, fmt.Errorf("invalid provider ID %q, expected inspace://<location>/<vm-uuid>", value)
	}
	return ID{Location: u.Host, VMUUID: vmUUID}, nil
}
