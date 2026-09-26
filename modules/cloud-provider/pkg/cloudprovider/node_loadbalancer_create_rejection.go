package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// Firewall create receipts are normally immutable after dispatch: no finite
// run of empty Lists proves that a timed-out or 5xx POST cannot commit later.
// A definitive client-error response is different. The provider evaluated and
// rejected the request, so once spaced exact-name reads also prove the
// deterministic name absent, the receipt may return to its staged state and
// the normal path may issue a fresh create through full pre-dispatch
// authority. The rejection marker is bound to the exact issued receipt value,
// so it can never authorize a later or concurrent attempt.
const (
	annotationNodeLoadBalancerShardFWCreateRejected = "service.inspace.cloud/node-lb-shard-firewall-create-rejected"
	annotationNodeLoadBalancerICMPCreateRejected    = "service.inspace.cloud/node-lb-icmp-create-rejected"
	annotationNodeLoadBalancerPendingFWRejected     = "service.inspace.cloud/node-lb-pending-firewall-create-rejected"
)

// errNodeLoadBalancerCreateAbsentAfterResponse is wrapped by the post-response
// create readbacks when the deterministic name is absent. It is the only
// readback outcome that may be combined with a definitive rejection.
var errNodeLoadBalancerCreateAbsentAfterResponse = errors.New("exact name absence readback")

// nodeLoadBalancerCreateDefinitivelyRejected accepts only complete 4xx API
// responses that mean the provider refused the request. Timeouts, conflicts,
// too-early, rate limits, client-closed requests, every 5xx, transport errors,
// and incomplete or malformed error bodies remain ambiguous.
func nodeLoadBalancerCreateDefinitivelyRejected(err error) bool {
	var apiErr *inspace.APIError
	if !errors.As(err, &apiErr) || apiErr.ResponseBodyIncomplete || apiErr.ResponseBodyMalformed {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly, http.StatusTooManyRequests, 499:
		return false
	}
	return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

// nodeLoadBalancerRejectedCreateAbsenceNotBefore delays the first absence
// observation for a rejected create until the SDK mutation timeout has passed
// since issue. A provider that nevertheless committed the POST therefore gets
// that full interval plus the spaced confirmations to make it visible, and the
// visible firewall is adopted instead of duplicated.
func nodeLoadBalancerRejectedCreateAbsenceNotBefore(issuedAt string) (time.Time, error) {
	issued, err := time.Parse(time.RFC3339Nano, issuedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("node load balancer: invalid rejected firewall create timestamp %q: %w", issuedAt, err)
	}
	return issued.Add(nodeLoadBalancerShardFirewallMutationTimeout), nil
}

func nodeLoadBalancerCreateRejectionProvable(createErr, readbackErr error) bool {
	return nodeLoadBalancerCreateDefinitivelyRejected(createErr) &&
		errors.Is(readbackErr, errNodeLoadBalancerCreateAbsentAfterResponse)
}

// markShardFirewallCreateRejected binds a definitive create rejection to the
// exact issued shard receipt.
func (c *nodeLoadBalancerController) markShardFirewallCreateRejected(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
) error {
	issuedAt := expected[annotationNodeLoadBalancerShardFWIssuedAt]
	if ownerUID == "" || issuedAt == "" {
		return errors.New("node load balancer: incomplete shard firewall create receipt for rejection")
	}
	_, _, err := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
		for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
			if values[key] != expected[key] {
				return false, errors.New("node load balancer: shard firewall create receipt changed before rejection was recorded")
			}
		}
		values[annotationNodeLoadBalancerShardFWCreateRejected] = issuedAt
		delete(values, annotationNodeLoadBalancerShardFWCreateAbsent)
		delete(values, annotationNodeLoadBalancerShardFWCreateChecked)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: record definitive shard firewall create rejection: %w", err)
	}
	return nil
}

// retireRejectedShardFirewallCreate records spaced exact-name absence for a
// definitively rejected create and, once proven, returns the receipt to its
// staged state. The caller has just observed the deterministic name absent.
func (c *nodeLoadBalancerController) retireRejectedShardFirewallCreate(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	annotations map[string]string,
) error {
	issuedAt := annotations[annotationNodeLoadBalancerShardFWIssuedAt]
	notBefore, err := nodeLoadBalancerRejectedCreateAbsenceNotBefore(issuedAt)
	if err != nil {
		return err
	}
	confirmed, _, err := c.recordManagedNodePoolFirewallAbsenceForUID(
		ctx, shard, ownerUID,
		annotationNodeLoadBalancerShardFWCreateAbsent,
		annotationNodeLoadBalancerShardFWCreateChecked,
		time.Now().UTC(), notBefore,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf(
			"node load balancer: shard firewall create issued at %s was definitively rejected but remains ambiguous until spaced exact-name absence is proven; refusing a second paid create until then",
			issuedAt,
		)
	}
	expected := nodeLoadBalancerShardFirewallMutationExpected(annotations, issuedAt)
	_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
		for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
			if values[key] != expected[key] {
				return false, errors.New("node load balancer: shard firewall create receipt changed during rejection absence proof")
			}
		}
		if values[annotationNodeLoadBalancerShardFWCreateRejected] != issuedAt {
			return false, errors.New("node load balancer: shard firewall create rejection changed during absence proof")
		}
		count, parseErr := strconv.Atoi(values[annotationNodeLoadBalancerShardFWCreateAbsent])
		if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
			return false, errors.New("node load balancer: shard firewall create absence is no longer confirmed")
		}
		for _, key := range []string{
			annotationNodeLoadBalancerShardFWIssuedAt,
			annotationNodeLoadBalancerShardFWCreateRejected,
			annotationNodeLoadBalancerShardFWCreateAbsent,
			annotationNodeLoadBalancerShardFWCreateChecked,
		} {
			delete(values, key)
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: retire definitively rejected shard firewall create: %w", err)
	}
	return nil
}

// markClusterICMPCreateRejected binds a definitive create rejection to the
// exact issued cluster ICMP receipt.
func (c *nodeLoadBalancerController) markClusterICMPCreateRejected(
	ctx context.Context,
	nodeClassName string,
	ownerUID types.UID,
	expected map[string]string,
) error {
	issuedAt := expected[annotationNodeLoadBalancerICMPCreateIssued]
	if ownerUID == "" || issuedAt == "" {
		return errors.New("node load balancer: incomplete cluster ICMP create receipt for rejection")
	}
	changed, err := c.mutateManagedNodeClassICMPCreateForUID(ctx, nodeClassName, ownerUID, expected, func(values map[string]string) {
		values[annotationNodeLoadBalancerICMPCreateRejected] = issuedAt
		delete(values, annotationNodeLoadBalancerICMPAbsent)
		delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
	})
	if err != nil {
		return fmt.Errorf("node load balancer: record definitive cluster ICMP create rejection: %w", err)
	}
	if !changed {
		return errors.New("node load balancer: cluster ICMP create rejection was not recorded")
	}
	return nil
}

// confirmRejectedClusterICMPCreateAbsent records one spaced exact-name absence
// observation for a definitively rejected cluster ICMP create. The caller has
// just observed the deterministic name absent and clears the pending identity
// only after this reports confirmation.
func (c *nodeLoadBalancerController) confirmRejectedClusterICMPCreateAbsent(
	ctx context.Context,
	nodeClassName string,
	ownerUID types.UID,
	createIssued string,
) (bool, error) {
	notBefore, err := nodeLoadBalancerRejectedCreateAbsenceNotBefore(createIssued)
	if err != nil {
		return false, err
	}
	confirmed, _, err := c.recordNodeClassFirewallAbsenceForUID(
		ctx, nodeClassName, ownerUID,
		annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
		time.Now().UTC(), notBefore,
	)
	if err != nil || confirmed {
		return confirmed, err
	}
	return false, fmt.Errorf(
		"node load balancer: cluster ICMP firewall create issued at %s was definitively rejected but remains ambiguous until spaced exact-name absence is proven; refusing a second paid create until then",
		createIssued,
	)
}

// markServiceFirewallCreateRejected binds a definitive create rejection to the
// exact issued Service firewall token.
func (c *nodeLoadBalancerController) markServiceFirewallCreateRejected(
	ctx context.Context,
	service *corev1.Service,
	token, issuedAt string,
) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] != token ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != issuedAt ||
			copy.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" {
			return false, errors.New("node load balancer: Service firewall create receipt changed before rejection was recorded")
		}
		copy.Annotations[annotationNodeLoadBalancerPendingFWRejected] = token
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: record definitive Service firewall create rejection: %w", err)
	}
	return nil
}

// retireRejectedServiceFirewallCreate records spaced exact-name absence for a
// definitively rejected Service firewall create and, once proven, returns the
// pending identity to its staged (not issued) state. The caller has just
// observed the deterministic name absent.
func (c *nodeLoadBalancerController) retireRejectedServiceFirewallCreate(
	ctx context.Context,
	service *corev1.Service,
	token, issuedAt string,
) error {
	notBefore, err := nodeLoadBalancerRejectedCreateAbsenceNotBefore(issuedAt)
	if err != nil {
		return err
	}
	confirmed, _, err := c.recordFirewallAbsence(
		ctx,
		service,
		annotationNodeLoadBalancerPendingFWAbsent,
		annotationNodeLoadBalancerPendingFWChecked,
		time.Now().UTC(),
		notBefore,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf(
			"node load balancer: Service firewall create attempt %s issued at %s was definitively rejected but remains ambiguous until spaced exact-name absence is proven; refusing a second paid create until then",
			token, issuedAt,
		)
	}
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] != token ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != issuedAt ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWRejected] != token ||
			copy.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" {
			return false, errors.New("node load balancer: Service firewall create receipt changed during rejection absence proof")
		}
		count, parseErr := strconv.Atoi(copy.Annotations[annotationNodeLoadBalancerPendingFWAbsent])
		if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
			return false, errors.New("node load balancer: Service firewall create absence is no longer confirmed")
		}
		for _, key := range []string{
			annotationNodeLoadBalancerPendingFWIssued,
			annotationNodeLoadBalancerPendingFWIssuedAt,
			annotationNodeLoadBalancerPendingFWRejected,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
		} {
			delete(copy.Annotations, key)
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: retire definitively rejected Service firewall create: %w", err)
	}
	return nil
}
