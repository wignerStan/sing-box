package route

import (
	"sync"
	"testing"
)

func TestAutoRedirectOutputMarkLease(t *testing.T) {
	manager := new(NetworkManager)
	if err := manager.RegisterAutoRedirectOutputMark(0); err == nil {
		t.Fatal("accepted a zero output mark")
	}
	if err := manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAutoRedirectOutputMark(0x200); err == nil {
		t.Fatal("accepted a second output mark owner")
	}
	if err := manager.UnregisterAutoRedirectOutputMark(0x200); err == nil {
		t.Fatal("released an output mark with the wrong owner value")
	}
	if mark := manager.AutoRedirectOutputMark(); mark != 0x100 {
		t.Fatalf("output mark = %#x, want %#x", mark, uint32(0x100))
	}
	if err := manager.UnregisterAutoRedirectOutputMark(0x100); err != nil {
		t.Fatal(err)
	}
	if mark := manager.AutoRedirectOutputMark(); mark != 0 {
		t.Fatalf("released output mark = %#x, want 0", mark)
	}
}

func TestAutoRedirectOutputMarkConcurrentRead(t *testing.T) {
	manager := new(NetworkManager)
	const iterations = 10_000
	var readers sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		readers.Go(func() {
			<-start
			for range iterations {
				mark := manager.AutoRedirectOutputMark()
				if mark != 0 && mark != 0x100 {
					t.Errorf("unexpected output mark %#x", mark)
					return
				}
			}
		})
	}
	close(start)
	for range iterations {
		if err := manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
			t.Fatal(err)
		}
		if err := manager.UnregisterAutoRedirectOutputMark(0x100); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}
