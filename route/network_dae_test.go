package route

import "testing"

func TestRegisterAutoRedirectOutputMarkIdempotent(t *testing.T) {
	manager := &NetworkManager{}
	if err := manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
		t.Fatalf("register identical mark: %v", err)
	}
	if err := manager.RegisterAutoRedirectOutputMark(0x101); err == nil {
		t.Fatal("register different mark succeeded")
	}
}
