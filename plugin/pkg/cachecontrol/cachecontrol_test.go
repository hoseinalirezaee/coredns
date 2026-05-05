package cachecontrol

import (
	"context"
	"testing"
)

func TestZonefileMarker(t *testing.T) {
	ctx := ContextWithBypassMarker(context.Background())
	if IsZonefile(ctx) {
		t.Fatal("new marker should not be marked")
	}

	MarkZonefile(ctx)
	if !IsZonefile(ctx) {
		t.Fatal("expected zonefile marker to be set")
	}
}

func TestMarkZonefileWithoutMarker(t *testing.T) {
	ctx := context.Background()
	MarkZonefile(ctx)
	if IsZonefile(ctx) {
		t.Fatal("context without marker should not report zonefile")
	}
}
