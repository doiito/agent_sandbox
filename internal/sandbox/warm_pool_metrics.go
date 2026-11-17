package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

func (m *Manager) WarmPoolStatus() (WarmPoolSnapshot, error) {
	if m.catalog != nil && m.owner == nil {
		return m.catalog.snapshot(), nil
	}
	if m.pool == nil {
		return WarmPoolSnapshot{Enabled: false, Healthy: true}, nil
	}
	return m.pool.snapshot(), nil
}

func (m *Manager) WarmPoolStatusContext(ctx context.Context) (WarmPoolSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return WarmPoolSnapshot{}, err
	}
	return m.WarmPoolStatus()
}

func (c LauncherClient) WarmPoolStatus() (WarmPoolSnapshot, error) {
	return c.WarmPoolStatusContext(context.Background())
}

func (c LauncherClient) WarmPoolStatusContext(parent context.Context) (WarmPoolSnapshot, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "warm-status"})
	if err != nil {
		return WarmPoolSnapshot{}, err
	}
	if response.WarmPool == nil || response.Error != "" {
		return WarmPoolSnapshot{}, errors.New("warm pool status unavailable")
	}
	return *response.WarmPool, nil
}

func writeWarmPoolMetrics(w io.Writer, s WarmPoolSnapshot) {
	if !s.Enabled {
		return
	}
	available := 0
	if s.Healthy {
		available = 1
	}
	fmt.Fprintf(w, "# TYPE osv_sandbox_warm_pool_available gauge\nosv_sandbox_warm_pool_available %d\n", available)
	fmt.Fprintf(w, "# TYPE osv_sandbox_warm_pool_hits_total counter\nosv_sandbox_warm_pool_hits_total %d\n", s.Hits)
	fmt.Fprintf(w, "# TYPE osv_sandbox_warm_pool_refill_failures_total counter\nosv_sandbox_warm_pool_refill_failures_total %d\n", s.RefillFailures)
	for _, profile := range s.Profiles {
		fmt.Fprintf(w, "osv_sandbox_warm_pool_ready{profile=%q} %d\nosv_sandbox_warm_pool_booting{profile=%q} %d\nosv_sandbox_warm_pool_desired{profile=%q} %d\n", profile.Name, profile.Ready, profile.Name, profile.Booting, profile.Name, profile.Desired)
	}
	for metric, values := range map[string]map[string]uint64{"misses": s.Misses, "discarded": s.Discarded} {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(w, "osv_sandbox_warm_pool_%s_total{reason=%q} %d\n", metric, key, values[key])
		}
	}
}
