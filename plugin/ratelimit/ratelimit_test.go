package ratelimit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBucketBurstAndRefill(t *testing.T) {
	l := &limiter{rate: 100, burst: 200, buckets: make(map[string]*bucket)}
	now := time.Unix(100, 0)
	if !l.allow("192.0.2.1", 200, now) {
		t.Fatal("expected initial burst to be allowed")
	}
	if l.allow("192.0.2.1", 1, now) {
		t.Fatal("expected exhausted bucket to reject")
	}
	if !l.allow("192.0.2.1", 100, now.Add(time.Second)) {
		t.Fatal("expected one second of refill to be allowed")
	}
}

func TestReadExemptionsSupportsIPCIDRAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exempt.txt")
	if err := os.WriteFile(path, []byte("# comment\n192.0.2.10\n2001:db8::/32 # v6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := readExemptions(path, "198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nets) != 3 {
		t.Fatalf("expected 3 networks, got %d", len(set.nets))
	}
}

func TestReadExemptionsRejectsInvalidEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exempt.txt")
	if err := os.WriteFile(path, []byte("not-an-ip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readExemptions(path, ""); err == nil {
		t.Fatal("expected invalid exemption to fail")
	}
}
