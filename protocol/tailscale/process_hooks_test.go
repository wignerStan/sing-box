//go:build with_gvisor

package tailscale

import "testing"

func TestProcessHookLeaseRejectsSecondEndpoint(t *testing.T) {
	first := &Endpoint{}
	second := &Endpoint{}
	firstLease, err := acquireProcessHookLease(first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(firstLease.Release)
	if secondLease, acquireErr := acquireProcessHookLease(second); acquireErr == nil {
		secondLease.Release()
		t.Fatal("second endpoint unexpectedly acquired process-global Tailscale hooks")
	}
	firstLease.Release()
	secondLease, err := acquireProcessHookLease(second)
	if err != nil {
		t.Fatalf("second endpoint could not acquire hooks after release: %v", err)
	}
	secondLease.Release()
	secondLease.Release()
}
