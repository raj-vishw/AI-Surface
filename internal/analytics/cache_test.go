package analytics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCacheKey_DiffersAcrossTargets(t *testing.T) {
	r := TimeRange{Start: time.Now(), End: time.Now().Add(time.Hour), Interval: "hour"}
	k1 := CacheKey(uuid.New(), "overview", r, "abc")
	k2 := CacheKey(uuid.New(), "overview", r, "abc")
	if k1 == k2 {
		t.Fatal("CacheKey produced the same key for two different targets — cache isolation is broken")
	}
}

func TestCacheKey_DiffersAcrossMetricsAndFilters(t *testing.T) {
	target := uuid.New()
	r := TimeRange{Start: time.Now(), End: time.Now().Add(time.Hour), Interval: "hour"}
	base := CacheKey(target, "alerts", r, "f1")
	if CacheKey(target, "findings", r, "f1") == base {
		t.Error("CacheKey does not vary by metric")
	}
	if CacheKey(target, "alerts", r, "f2") == base {
		t.Error("CacheKey does not vary by filters hash")
	}
}

func TestCache_GetSetRoundTrip(t *testing.T) {
	c := NewCache(time.Minute)
	c.Set("k", 42)
	v, ok := c.Get("k")
	if !ok || v.(int) != 42 {
		t.Fatalf("Get after Set = (%v, %v), want (42, true)", v, ok)
	}
}

func TestCache_ExpiresAfterTTL(t *testing.T) {
	c := NewCache(10 * time.Millisecond)
	c.Set("k", "v")
	time.Sleep(30 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected the entry to have expired")
	}
}

func TestCache_MissForUnknownKey(t *testing.T) {
	c := NewCache(time.Minute)
	if _, ok := c.Get("nonexistent"); ok {
		t.Fatal("expected a cache miss for a key never set")
	}
}
