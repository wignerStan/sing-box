// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"reflect"
	"testing"
)

func TestSplitList(t *testing.T) {
	if got, want := splitList(" eth0, ,eth1 "), []string{"eth0", "eth1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	if got := splitList(" "); got != nil {
		t.Fatalf("empty splitList = %#v", got)
	}
}

func TestDoctorRejectsPortOverflowBeforePreflight(t *testing.T) {
	if err := doctor([]string{"--port", "70000"}); err == nil {
		t.Fatal("overflowing port was accepted")
	}
}
