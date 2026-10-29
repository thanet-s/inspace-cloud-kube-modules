package cloudprovider

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A stamp the settle delay counts from that cannot be read must never read as
// settled, and the Service pass must say so on every member instead of waiting
// without a word.
func TestPerVMCorruptSettleStampIsAnnouncedOnTheMembers(t *testing.T) {
	for _, key := range []string{annotationVMFirewallAppliedAt, annotationVMFirewallAttachedAt} {
		t.Run(strings.TrimPrefix(key, vmFirewallAnnotationPrefix), func(t *testing.T) {
			f := newPerVMPublicNodeLocalFixture(t, 1)
			_, vm0, _, _ := publicNodeLocalFixtureNode(0)
			if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, f.anchorOf(t, vm0), func(cm *corev1.ConfigMap) (bool, error) {
				cm.Annotations[key] = "not a time"
				return true, nil
			}); err != nil {
				t.Fatal(err)
			}
			err := f.controller.vmFirewallSettleGate(f.ctx, f.current(t), []string{vm0})
			if err == nil {
				t.Fatal("a corrupt stamp must never read as settled")
			}
			var settling *errPublicNodeLocalVMFirewallSettling
			if errors.As(err, &settling) {
				t.Fatalf("a corrupt stamp is a fault, not a wait: %v", err)
			}
			if !errors.Is(err, errVMFirewallLedgerCorrupt) {
				t.Fatalf("error = %v, want a corrupt ledger fault", err)
			}
			var found bool
			for _, event := range f.eventsOf(t, vmFirewallDriftReason) {
				if strings.Contains(event.Message, key) && strings.Contains(event.Message, vmFirewallAnchorName(vm0)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s Event names the anchor and %s", vmFirewallDriftReason, key)
			}
		})
	}
}

func (f *publicNodeLocalFixtureT) eventsOf(t *testing.T, reason string) []corev1.Event {
	t.Helper()
	list, err := f.provider.kubeClient.CoreV1().Events(f.service.Namespace).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out []corev1.Event
	for _, event := range list.Items {
		if event.Reason == reason {
			out = append(out, event)
		}
	}
	return out
}
