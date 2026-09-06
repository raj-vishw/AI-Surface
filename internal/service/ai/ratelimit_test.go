package ai

import "testing"

func TestRateLimiter_EnforcesPerUserLimit(t *testing.T) {
	l := newRateLimiter(RateLimitConfig{PerUserPerMinute: 2, PerTargetPerMinute: 100, MaxConcurrent: 100})
	if !l.Allow("analyst-1", "t1") {
		t.Fatal("expected first call to be allowed")
	}
	l.Release()
	if !l.Allow("analyst-1", "t1") {
		t.Fatal("expected second call to be allowed")
	}
	l.Release()
	if l.Allow("analyst-1", "t1") {
		t.Fatal("expected third call within the window to be denied")
	}
}

func TestRateLimiter_EnforcesPerTargetLimit(t *testing.T) {
	l := newRateLimiter(RateLimitConfig{PerUserPerMinute: 100, PerTargetPerMinute: 1, MaxConcurrent: 100})
	if !l.Allow("analyst-1", "t1") {
		t.Fatal("expected first call to be allowed")
	}
	l.Release()
	if l.Allow("analyst-2", "t1") {
		t.Fatal("expected a different user hitting the same target to be denied once the target limit is reached")
	}
}

func TestRateLimiter_EnforcesConcurrencyLimit(t *testing.T) {
	l := newRateLimiter(RateLimitConfig{PerUserPerMinute: 100, PerTargetPerMinute: 100, MaxConcurrent: 1})
	if !l.Allow("analyst-1", "t1") {
		t.Fatal("expected first concurrent call to be allowed")
	}
	if l.Allow("analyst-2", "t2") {
		t.Fatal("expected a second concurrent call to be denied while the first is still in flight")
	}
	l.Release()
	if !l.Allow("analyst-2", "t2") {
		t.Fatal("expected a call to be allowed after the first was released")
	}
}

func TestRateLimitConfig_EffectiveAppliesDefaults(t *testing.T) {
	eff := RateLimitConfig{}.Effective()
	if eff.PerUserPerMinute <= 0 || eff.PerTargetPerMinute <= 0 || eff.MaxConcurrent <= 0 {
		t.Errorf("Effective() left a zero value: %+v", eff)
	}
}
