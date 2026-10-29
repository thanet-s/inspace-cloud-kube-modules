package cloudprovider

import (
	"sync"
	"testing"
	"time"
)

// testAssignFenceClock is a wall clock that never steps back. An assignment
// fence is stamped by one call and judged by a later one; a wall clock that is
// corrected backwards between them (a VM under load, a resynced host) makes a
// fresh fence look as if it were written in the future, and the fixture fails
// with "durable firewall assignment fence is not fresh".
var testAssignFenceClock = newNonSteppingClock(time.Now)

// Every controller the tests build, 165 literals of them, reads the fence
// clock through assignFenceWall, so none can be left on the raw wall clock.
func init() { assignFenceWall = testAssignFenceClock }

func newNonSteppingClock(wall func() time.Time) func() time.Time {
	var mu sync.Mutex
	var last time.Time
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if now := wall(); now.After(last) {
			last = now
		}
		return last
	}
}

func TestNonSteppingClockNeverGoesBackwards(t *testing.T) {
	wall := []time.Time{
		time.Date(2026, 10, 29, 12, 0, 1, 0, time.UTC),
		time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), // the wall clock was stepped back
		time.Date(2026, 10, 29, 12, 0, 2, 0, time.UTC),
	}
	index := 0
	clock := newNonSteppingClock(func() time.Time { index++; return wall[index-1] })
	first, second, third := clock(), clock(), clock()
	if second.Before(first) || !second.Equal(first) {
		t.Fatalf("a backwards step leaked: %s then %s", first, second)
	}
	if !third.Equal(wall[2]) {
		t.Fatalf("the clock did not move on: %s", third)
	}
}

func TestAssignFenceClockDefaultsToTheWallClock(t *testing.T) {
	c := &nodeLoadBalancerController{}
	before := time.Now().UTC()
	got := c.assignFenceClock()
	if got.Before(before) || time.Since(got) > time.Minute || got.Location() != time.UTC {
		t.Fatalf("default fence clock = %s", got)
	}
	fixed := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	c.assignFenceNow = func() time.Time { return fixed }
	if got := c.assignFenceClock(); !got.Equal(fixed) {
		t.Fatalf("injected fence clock = %s", got)
	}
}
