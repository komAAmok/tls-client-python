package main

import (
	"sync"
	"testing"
	"time"
)

// resetPoolForTest clears the client pool and resets all metrics to zero.
// Must be called at the start of each test to isolate state.
func resetPoolForTest() {
	clientPool.Range(func(key, value any) bool {
		clientPool.Delete(key)
		return true
	})
	totalEvictions.Store(0)
	lastEvictionCount.Store(0)
	lastEvictionTime.Store(0)
	poolTTLNs.Store(int64(5 * time.Minute))
	poolScanIntervalNs.Store(int64(60 * time.Second))
}

// TestEvictStaleEntries_EmptyPool verifies that evicting an empty pool
// produces zero metrics.
func TestEvictStaleEntries_EmptyPool(t *testing.T) {
	resetPoolForTest()

	evictStaleEntries()

	if totalEvictions.Load() != 0 {
		t.Errorf("totalEvictions = %d, want 0", totalEvictions.Load())
	}
	if lastEvictionCount.Load() != 0 {
		t.Errorf("lastEvictionCount = %d, want 0", lastEvictionCount.Load())
	}
	if lastEvictionTime.Load() == 0 {
		t.Error("lastEvictionTime should be set even when nothing is evicted")
	}
}

// TestEvictStaleEntries_StaleEntriesRemoved verifies that entries with
// lastAccess older than poolTTL are evicted and counters are incremented.
func TestEvictStaleEntries_StaleEntriesRemoved(t *testing.T) {
	resetPoolForTest()

	// Set a very short TTL so entries become stale immediately.
	poolTTLNs.Store(int64(50 * time.Millisecond))

	// Insert entries with an old lastAccess timestamp.
	oldTime := time.Now().Add(-time.Hour).UnixNano()
	for i := 0; i < 5; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(oldTime)
		clientPool.Store("stale-"+string(rune('a'+i)), pe)
	}

	evictStaleEntries()

	if totalEvictions.Load() != 5 {
		t.Errorf("totalEvictions = %d, want 5", totalEvictions.Load())
	}
	if lastEvictionCount.Load() != 5 {
		t.Errorf("lastEvictionCount = %d, want 5", lastEvictionCount.Load())
	}
	if lastEvictionTime.Load() == 0 {
		t.Error("lastEvictionTime should be set after eviction")
	}

	// Verify entries are removed.
	var remaining int
	clientPool.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != 0 {
		t.Errorf("%d entries remain in pool, want 0", remaining)
	}
}

// TestEvictStaleEntries_RecentEntriesSurvive verifies that entries accessed
// recently are NOT evicted.
func TestEvictStaleEntries_RecentEntriesSurvive(t *testing.T) {
	resetPoolForTest()

	// Set a reasonable TTL.
	poolTTLNs.Store(int64(5 * time.Second))

	// Insert entries with a recent lastAccess timestamp.
	now := time.Now().UnixNano()
	for i := 0; i < 3; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(now)
		clientPool.Store("recent-"+string(rune('a'+i)), pe)
	}

	evictStaleEntries()

	if totalEvictions.Load() != 0 {
		t.Errorf("totalEvictions = %d, want 0 (recent entries should survive)", totalEvictions.Load())
	}
	if lastEvictionCount.Load() != 0 {
		t.Errorf("lastEvictionCount = %d, want 0", lastEvictionCount.Load())
	}

	var remaining int
	clientPool.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != 3 {
		t.Errorf("%d entries remain, want 3", remaining)
	}
}

// TestEvictStaleEntries_Mixed verifies that only stale entries are evicted
// when the pool contains a mix of recent and stale entries.
func TestEvictStaleEntries_Mixed(t *testing.T) {
	resetPoolForTest()

	poolTTLNs.Store(int64(100 * time.Millisecond))

	now := time.Now().UnixNano()
	oldTime := time.Now().Add(-time.Hour).UnixNano()

	// Insert 3 recent entries.
	for i := 0; i < 3; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(now)
		clientPool.Store("recent-"+string(rune('a'+i)), pe)
	}
	// Insert 2 stale entries.
	for i := 0; i < 2; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(oldTime)
		clientPool.Store("stale-"+string(rune('a'+i)), pe)
	}

	evictStaleEntries()

	if totalEvictions.Load() != 2 {
		t.Errorf("totalEvictions = %d, want 2", totalEvictions.Load())
	}
	if lastEvictionCount.Load() != 2 {
		t.Errorf("lastEvictionCount = %d, want 2", lastEvictionCount.Load())
	}

	var remaining int
	clientPool.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != 3 {
		t.Errorf("%d entries remain, want 3", remaining)
	}
}

// TestGetPoolStats verifies that GetPoolStats returns the correct metrics,
// entry count, and configuration values.
func TestGetPoolStats(t *testing.T) {
	resetPoolForTest()

	poolTTLNs.Store(int64(120 * time.Second))
	poolScanIntervalNs.Store(int64(30 * time.Second))
	totalEvictions.Store(42)
	lastEvictionCount.Store(7)
	lastEvictionTime.Store(1700000000000000000)

	// Insert 3 entries.
	for i := 0; i < 3; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(time.Now().UnixNano())
		clientPool.Store("entry-"+string(rune('a'+i)), pe)
	}

	var stats C.PoolStats
	GetPoolStats(&stats)

	if v := int64(stats.total_evictions); v != 42 {
		t.Errorf("total_evictions = %d, want 42", v)
	}
	if v := int64(stats.last_eviction_count); v != 7 {
		t.Errorf("last_eviction_count = %d, want 7", v)
	}
	if v := int64(stats.last_eviction_time); v != 1700000000000000000 {
		t.Errorf("last_eviction_time = %d, want 1700000000000000000", v)
	}
	if v := int64(stats.pool_entry_count); v != 3 {
		t.Errorf("pool_entry_count = %d, want 3", v)
	}
	if v := int64(stats.pool_ttl_seconds); v != 120 {
		t.Errorf("pool_ttl_seconds = %d, want 120", v)
	}
	if v := int64(stats.pool_scan_interval_seconds); v != 30 {
		t.Errorf("pool_scan_interval_seconds = %d, want 30", v)
	}

	// Test nil pointer guard.
	GetPoolStats(nil) // should not panic
}

// TestGetPoolStats_NilStats verifies GetPoolStats does not crash with nil.
func TestGetPoolStats_NilStats(t *testing.T) {
	resetPoolForTest()
	// Must not panic.
	GetPoolStats(nil)
}

// TestEvictStaleEntries_CumulativeTotal verifies that totalEvictions is
// cumulative across multiple eviction cycles.
func TestEvictStaleEntries_CumulativeTotal(t *testing.T) {
	resetPoolForTest()

	poolTTLNs.Store(int64(50 * time.Millisecond))
	oldTime := time.Now().Add(-time.Hour).UnixNano()

	// First cycle: evict 3 entries.
	for i := 0; i < 3; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(oldTime)
		clientPool.Store("batch1-"+string(rune('a'+i)), pe)
	}
	evictStaleEntries()

	if totalEvictions.Load() != 3 {
		t.Errorf("after first eviction: totalEvictions = %d, want 3", totalEvictions.Load())
	}

	// Second cycle: evict 2 more entries.
	for i := 0; i < 2; i++ {
		pe := &poolEntry{}
		pe.lastAccess.Store(oldTime)
		clientPool.Store("batch2-"+string(rune('a'+i)), pe)
	}
	evictStaleEntries()

	if totalEvictions.Load() != 5 {
		t.Errorf("after second eviction: totalEvictions = %d, want 5", totalEvictions.Load())
	}
	if lastEvictionCount.Load() != 2 {
		t.Errorf("lastEvictionCount = %d, want 2", lastEvictionCount.Load())
	}
}

// TestPoolEntry_ConcurrentAccess verifies that poolEntry.lastAccess is safe
// for concurrent reads/writes.
func TestPoolEntry_ConcurrentAccess(t *testing.T) {
	resetPoolForTest()

	pe := &poolEntry{}
	pe.lastAccess.Store(time.Now().UnixNano())

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			// Concurrent stores should not race.
			pe.lastAccess.Store(time.Now().UnixNano())
			_ = pe.lastAccess.Load()
		}()
	}
	wg.Wait()
}
