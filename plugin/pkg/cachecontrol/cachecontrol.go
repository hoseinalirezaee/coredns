// Package cachecontrol provides per-request signals that downstream plugins can
// use to influence cache behavior without importing the cache plugin.
package cachecontrol

import (
	"context"
	"sync/atomic"
)

type markerKey struct{}

type marker struct {
	zonefile atomic.Bool
}

// ContextWithBypassMarker returns a child context with a fresh cache bypass marker.
func ContextWithBypassMarker(ctx context.Context) context.Context {
	return context.WithValue(ctx, markerKey{}, &marker{})
}

// MarkZonefile marks the current response as originating from a zonefile.
func MarkZonefile(ctx context.Context) {
	m, ok := ctx.Value(markerKey{}).(*marker)
	if !ok || m == nil {
		return
	}
	m.zonefile.Store(true)
}

// IsZonefile reports whether the current response has been marked as zonefile-backed.
func IsZonefile(ctx context.Context) bool {
	m, ok := ctx.Value(markerKey{}).(*marker)
	if !ok || m == nil {
		return false
	}
	return m.zonefile.Load()
}
