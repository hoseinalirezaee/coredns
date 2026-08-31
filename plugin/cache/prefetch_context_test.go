package cache

import (
	"context"
	"testing"
)

func TestPrefetchContextMarker(t *testing.T) {
	ctx := context.Background()
	if IsPrefetchContext(ctx) {
		t.Fatal("plain context must not be marked as prefetch")
	}
	if !IsPrefetchContext(WithPrefetchContext(ctx)) {
		t.Fatal("marked context must be recognized as prefetch")
	}
}
