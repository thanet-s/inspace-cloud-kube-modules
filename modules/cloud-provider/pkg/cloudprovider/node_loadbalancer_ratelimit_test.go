package cloudprovider

import (
	"testing"
	"time"
)

func TestNodeLoadBalancerRateLimiterCapsBackoffAt60s(t *testing.T) {
	limiter := newNodeLoadBalancerRateLimiter()
	for i := 0; i < 40; i++ {
		delay := limiter.When("k")
		if i == 0 && delay < 5*time.Millisecond {
			t.Fatalf("first delay = %s, want at least 5ms", delay)
		}
		if delay > 60*time.Second {
			t.Fatalf("delay %d = %s, want at most 60s", i, delay)
		}
	}
}
