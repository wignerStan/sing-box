//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestOwnershipRecordValidation(t *testing.T) {
	valid := testOwnershipRecord()
	if err := validateOwnershipRecord(valid); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	tests := map[string]func(*ownershipRecord){
		"version":            func(record *ownershipRecord) { record.Version++ },
		"token":              func(record *ownershipRecord) { record.Token = "not-a-token" },
		"pid":                func(record *ownershipRecord) { record.PID = 0 },
		"namespace":          func(record *ownershipRecord) { record.Namespace = "other" },
		"namespace identity": func(record *ownershipRecord) { record.NamespaceInode = 0 },
		"host link":          func(record *ownershipRecord) { record.HostLink = "other" },
		"attachment":         func(record *ownershipRecord) { record.Attachments[0].Name = "foreign" },
		"interface":          func(record *ownershipRecord) { record.LANInterfaces[0] = "bad/name" },
		"wrong role":         func(record *ownershipRecord) { record.Attachments[1].Interface = "wan0" },
		"duplicate":          func(record *ownershipRecord) { record.Attachments = append(record.Attachments, record.Attachments[0]) },
		"sysctl path":        func(record *ownershipRecord) { record.Sysctls[0].Path = "/proc/sys/kernel/core_pattern" },
		"sysctl value":       func(record *ownershipRecord) { record.Sysctls[0].Applied = "unsafe" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := valid
			record.LANInterfaces = append([]string(nil), valid.LANInterfaces...)
			record.WANInterfaces = append([]string(nil), valid.WANInterfaces...)
			record.Attachments = append([]ownedAttachmentRecord(nil), valid.Attachments...)
			record.Sysctls = append([]sysctlMutation(nil), valid.Sysctls...)
			mutate(&record)
			if err := validateOwnershipRecord(record); err == nil {
				t.Fatal("invalid ownership record was accepted")
			}
		})
	}
	legacy := valid
	legacy.NamespaceDevice = 0
	legacy.NamespaceInode = 0
	if err := validateOwnershipRecord(legacy); err != nil {
		t.Fatalf("legacy record without namespace identity: %v", err)
	}
}

func TestOwnershipLeaseReleaseModes(t *testing.T) {
	originalDirectory := runtimeStateDirectory
	runtimeStateDirectory = t.TempDir()
	t.Cleanup(func() { runtimeStateDirectory = originalDirectory })

	lease, err := acquireOwnership(PreflightReport{})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Abandon(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ownerRecordPath())
	if err != nil {
		t.Fatal(err)
	}
	var record ownershipRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if !record.Released {
		t.Fatal("abandoned lease was not marked released")
	}

	if err := os.Remove(ownerRecordPath()); err != nil {
		t.Fatal(err)
	}
	lease, err = acquireOwnership(PreflightReport{})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ownerRecordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed lease left a record: %v", err)
	}
}

func TestMissingNetlinkErrorClassification(t *testing.T) {
	_, err := netlink.LinkByName("dae-does-not-exist")
	if err == nil {
		t.Fatal("unexpected test interface")
	}
	if !isMissingNetlinkError(err) {
		t.Fatalf("typed netlink not-found error was not recognized: %T: %v", err, err)
	}
}

func TestRemoveOwnershipRecordRejectsDifferentToken(t *testing.T) {
	originalDirectory := runtimeStateDirectory
	runtimeStateDirectory = t.TempDir()
	t.Cleanup(func() { runtimeStateDirectory = originalDirectory })

	lease, err := acquireOwnership(PreflightReport{})
	if err != nil {
		t.Fatal(err)
	}
	if err := removeOwnershipRecord("dae-ebpfinbound:ffeeddccbbaa99887766554433221100"); err == nil {
		t.Fatal("ownership record with a different token was removed")
	}
	if _, err := os.Stat(ownerRecordPath()); err != nil {
		t.Fatalf("ownership record was not preserved: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func testOwnershipRecord() ownershipRecord {
	return ownershipRecord{
		Version:         ownershipRecordVersion,
		Token:           "dae-ebpfinbound:00112233445566778899aabbccddeeff",
		PID:             123,
		BootID:          "test-boot",
		StartedAt:       time.Unix(1, 0).UTC(),
		Namespace:       captureNetNSName,
		NamespaceDevice: 1,
		NamespaceInode:  2,
		HostLink:        captureHostLink,
		PeerLink:        capturePeerLink,
		LANInterfaces:   []string{"lan0"},
		WANInterfaces:   []string{"wan0"},
		Attachments: []ownedAttachmentRecord{
			{
				Interface: captureHostLink,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(captureInternalTCMajor, 0x002),
				Name:      "dae_cap_host",
				ProgramID: 1,
			},
			{
				Interface: "lan0",
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(captureUserTCMajor, 0x101),
				Name:      "dae_cap_li_l2",
				ProgramID: 2,
			},
		},
		Sysctls: []sysctlMutation{{
			Path:     "/proc/sys/net/ipv4/conf/dae-ebpf0/rp_filter",
			Original: "2",
			Applied:  "0",
		}},
	}
}
