package cloudprovider

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPublicNodeLocalTransitionState(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantPhase   publicNodeLocalTransitionPhase
		wantErr     bool
	}{
		{name: "not serving", annotations: map[string]string{}, wantPhase: publicNodeLocalPhaseInactive},
		{name: "steady", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
		}, wantPhase: publicNodeLocalPhaseSteady},
		{name: "promoted keeps the previous firewall", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "b", annotationPublicNodeLocalActivePolicy: "h2",
			annotationNodeLoadBalancerPreviousFirewall: "11111111-1111-4111-8111-111111111111",
		}, wantPhase: publicNodeLocalPhasePromoted},
		{name: "union of a pool switch", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
			annotationPublicNodeLocalTargetPool: "b", annotationPublicNodeLocalTargetPolicy: "h1",
		}, wantPhase: publicNodeLocalPhaseUnion},
		{name: "union of a policy change", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
			annotationPublicNodeLocalTargetPool: "a", annotationPublicNodeLocalTargetPolicy: "h2",
		}, wantPhase: publicNodeLocalPhaseUnion},
		{name: "only the target pool", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
			annotationPublicNodeLocalTargetPool: "b",
		}, wantPhase: publicNodeLocalPhaseInvalid, wantErr: true},
		{name: "only the target policy", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
			annotationPublicNodeLocalTargetPolicy: "h2",
		}, wantPhase: publicNodeLocalPhaseInvalid, wantErr: true},
		{name: "target equals active", annotations: map[string]string{
			annotationPublicNodeLocalActivePool: "a", annotationPublicNodeLocalActivePolicy: "h1",
			annotationPublicNodeLocalTargetPool: "a", annotationPublicNodeLocalTargetPolicy: "h1",
		}, wantPhase: publicNodeLocalPhaseInvalid, wantErr: true},
		{name: "target without an activation", annotations: map[string]string{
			annotationPublicNodeLocalTargetPool: "b", annotationPublicNodeLocalTargetPolicy: "h1",
		}, wantPhase: publicNodeLocalPhaseInvalid, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: test.annotations}}
			state, err := publicNodeLocalTransition(service)
			if (err != nil) != test.wantErr {
				t.Fatalf("err = %v, want error %t", err, test.wantErr)
			}
			if state.Phase != test.wantPhase {
				t.Fatalf("phase = %v, want %v", state.Phase, test.wantPhase)
			}
			if state.Phase == publicNodeLocalPhaseUnion {
				if pool, policy := state.Work(); pool != test.annotations[annotationPublicNodeLocalTargetPool] ||
					policy != test.annotations[annotationPublicNodeLocalTargetPolicy] {
					t.Fatalf("work identity = %s/%s", pool, policy)
				}
			} else if state.Phase != publicNodeLocalPhaseInvalid {
				if pool, policy := state.Work(); pool != test.annotations[annotationPublicNodeLocalActivePool] ||
					policy != test.annotations[annotationPublicNodeLocalActivePolicy] {
					t.Fatalf("work identity = %s/%s", pool, policy)
				}
			}
		})
	}
}
