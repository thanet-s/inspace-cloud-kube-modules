// Package providerid owns the canonical InSpace Kubernetes provider-ID format.
package providerid

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const Scheme = "inspace"

var (
	locationPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

type ID struct {
	Location string
	UUID     string
}

func New(location, uuid string) (string, error) {
	id := ID{Location: location, UUID: strings.ToLower(uuid)}
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id.String(), nil
}

func Parse(value string) (ID, error) {
	const prefix = Scheme + "://"
	if !strings.HasPrefix(value, prefix) {
		return ID{}, fmt.Errorf("providerid: expected %q scheme", Scheme)
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), "/")
	if len(parts) != 2 {
		return ID{}, errors.New("providerid: expected inspace://<location>/<uuid>")
	}
	id := ID{Location: parts[0], UUID: strings.ToLower(parts[1])}
	if err := id.Validate(); err != nil {
		return ID{}, err
	}
	return id, nil
}

func (id ID) Validate() error {
	if !locationPattern.MatchString(id.Location) {
		return fmt.Errorf("providerid: invalid location %q", id.Location)
	}
	if !uuidPattern.MatchString(id.UUID) {
		return fmt.Errorf("providerid: invalid UUID %q", id.UUID)
	}
	return nil
}

func (id ID) String() string {
	return Scheme + "://" + id.Location + "/" + strings.ToLower(id.UUID)
}
