package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type splitViewBootstrapFloatingIPAPI struct {
	*fakeAPI
	exact    *inspace.FloatingIP
	exactErr error
	listed   []inspace.FloatingIP
}

func (a *splitViewBootstrapFloatingIPAPI) GetFloatingIP(
	context.Context,
	string,
	string,
) (*inspace.FloatingIP, error) {
	if a.exactErr != nil {
		return nil, a.exactErr
	}
	if a.exact == nil {
		return nil, errors.New("synthetic empty exact floating-IP response")
	}
	copy := *a.exact
	return &copy, nil
}

func (a *splitViewBootstrapFloatingIPAPI) ListFloatingIPs(
	context.Context,
	string,
	*inspace.FloatingIPFilters,
) ([]inspace.FloatingIP, error) {
	return append([]inspace.FloatingIP{}, a.listed...), nil
}

func bootstrapExactFloatingIPNotFound(address string) error {
	return &inspace.APIError{
		StatusCode:       http.StatusNotFound,
		Method:           http.MethodGet,
		Path:             "/v1/bkk01/network/ip_addresses/" + address,
		Message:          "not found",
		ExactLookup:      true,
		RequestedAddress: address,
	}
}

func TestBootstrapFloatingIPAuthorityRequiresExactAndListAgreement(t *testing.T) {
	base := inspace.FloatingIP{
		Address:          "203.0.113.20",
		Name:             "cluster-a-cp-0-ip",
		BillingAccountID: 42,
		Type:             "public",
		Enabled:          true,
	}
	assigned := base
	assigned.AssignedTo = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	assigned.AssignedToResourceType = "virtual_machine"
	assigned.AssignedToPrivateIP = "10.0.0.10"
	tombstone := base
	tombstone.IsDeleted = true

	tests := []struct {
		name       string
		exact      *inspace.FloatingIP
		exactErr   error
		listed     []inspace.FloatingIP
		wantAbsent bool
		wantError  bool
	}{
		{name: "active agreement", exact: &base, listed: []inspace.FloatingIP{base}},
		{name: "assigned agreement", exact: &assigned, listed: []inspace.FloatingIP{assigned}},
		{name: "404 and list absence", exactErr: bootstrapExactFloatingIPNotFound(base.Address), listed: []inspace.FloatingIP{}, wantAbsent: true},
		{name: "tombstone and list tombstone", exact: &tombstone, listed: []inspace.FloatingIP{tombstone}, wantAbsent: true},
		{name: "404 but list presence", exactErr: bootstrapExactFloatingIPNotFound(base.Address), listed: []inspace.FloatingIP{base}, wantError: true},
		{name: "tombstone but list presence", exact: &tombstone, listed: []inspace.FloatingIP{base}, wantError: true},
		{name: "exact presence but list absence", exact: &base, listed: []inspace.FloatingIP{}, wantError: true},
		{name: "state disagreement", exact: &base, listed: []inspace.FloatingIP{assigned}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseAPI := &fakeAPI{}
			api := &splitViewBootstrapFloatingIPAPI{
				fakeAPI: baseAPI,
				exact:   test.exact, exactErr: test.exactErr, listed: test.listed,
			}
			reconciler := &Reconciler{API: api}
			item, absent, _, err := reconciler.readExactFloatingIPInventory(
				context.Background(),
				"bkk01",
				base.Address,
			)
			if test.wantError {
				if err == nil || absent || item != nil {
					t.Fatalf("authority = %#v, absent=%t, err=%v; want fail-closed error", item, absent, err)
				}
				if len(baseAPI.events) != 0 {
					t.Fatalf("split read dispatched mutations: %v", baseAPI.events)
				}
				return
			}
			if err != nil || absent != test.wantAbsent {
				t.Fatalf("authority = %#v, absent=%t, err=%v", item, absent, err)
			}
		})
	}
}
