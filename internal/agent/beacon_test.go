package agent

import (
	"testing"
	"time"
)

func TestCapBackoffGrowsToMax(t *testing.T) {
	base, maxDelay := time.Second, 10*time.Second
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, time.Second},
		{1, 2 * time.Second},
		{3, 8 * time.Second},
		{4, 10 * time.Second},
		{20, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := capBackoff(base, maxDelay, tc.attempt); got != tc.want {
			t.Fatalf("capBackoff(attempt %d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestJitteredBounds(t *testing.T) {
	base := time.Second
	for i := 0; i < 200; i++ {
		d := jittered(base, 0.2)
		if d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatalf("jittered out of bounds: %v", d)
		}
	}
	if got := jittered(base, 0); got != base {
		t.Fatalf("zero jitter must be identity, got %v", got)
	}
}
