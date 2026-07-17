package cloudprovider

import (
	"context"
	"errors"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type splitViewStandardNLBFloatingIPAPI struct {
	*fakeAPI
	exact    *inspace.FloatingIP
	exactErr error
	listed   []inspace.FloatingIP
}

func (a *splitViewStandardNLBFloatingIPAPI) GetFloatingIP(
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

func (a *splitViewStandardNLBFloatingIPAPI) ListFloatingIPs(
	context.Context,
	string,
	*inspace.FloatingIPFilters,
) ([]inspace.FloatingIP, error) {
	return append([]inspace.FloatingIP{}, a.listed...), nil
}

func TestStandardNLBFloatingIPAuthorityRequiresExactAndListAgreement(t *testing.T) {
	service := testService()
	baseProvider := newTestProvider(t, &fakeAPI{})
	base := inspace.FloatingIP{
		Address:          "203.0.113.20",
		Name:             baseProvider.floatingIPName(service),
		BillingAccountID: 42,
		Type:             "public",
		Enabled:          true,
	}
	assigned := base
	assigned.AssignedTo = testLBUUID
	assigned.AssignedToResourceType = "load_balancer"
	assigned.AssignedToPrivateIP = "10.0.0.50"
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
		{name: "404 and list absence", exactErr: exactFloatingIPNotFound(base.Address), listed: []inspace.FloatingIP{}, wantAbsent: true},
		{name: "tombstone and list tombstone", exact: &tombstone, listed: []inspace.FloatingIP{tombstone}, wantAbsent: true},
		{name: "404 but list presence", exactErr: exactFloatingIPNotFound(base.Address), listed: []inspace.FloatingIP{base}, wantError: true},
		{name: "tombstone but list presence", exact: &tombstone, listed: []inspace.FloatingIP{base}, wantError: true},
		{name: "exact presence but list omission", exact: &base, listed: []inspace.FloatingIP{}, wantError: true},
		{name: "state disagreement", exact: &base, listed: []inspace.FloatingIP{assigned}, wantError: true},
		{name: "ownership name rebound", exactErr: exactFloatingIPNotFound(base.Address), listed: []inspace.FloatingIP{{
			Address: "203.0.113.21", Name: base.Name, BillingAccountID: 42, Type: "public", Enabled: true,
		}}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &splitViewStandardNLBFloatingIPAPI{
				fakeAPI: &fakeAPI{}, exact: test.exact, exactErr: test.exactErr, listed: test.listed,
			}
			provider := newTestProvider(t, api)
			item, absent, err := provider.readExactOwnedStandardNLBFloatingIP(
				context.Background(),
				service,
				base.Address,
			)
			if test.wantError {
				if err == nil || absent || item != nil {
					t.Fatalf("authority = %#v, absent=%t, err=%v; want fail-closed error", item, absent, err)
				}
				return
			}
			if err != nil || absent != test.wantAbsent {
				t.Fatalf("authority = %#v, absent=%t, err=%v", item, absent, err)
			}
			if test.wantAbsent && item != nil {
				t.Fatalf("absent authority returned item %#v", item)
			}
			if !test.wantAbsent && (item == nil || item.Address != base.Address) {
				t.Fatalf("present authority returned %#v", item)
			}
		})
	}
}
