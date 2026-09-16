//go:build linux && dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

type ownedTCAttachment struct{ record ownedAttachmentRecord }

func (r *captureRuntime) attachDatapath() ([]ownedTCAttachment, []func() error, error) {
	return nil, nil, stubBPFError()
}
func attachmentRecords([]ownedTCAttachment) []ownedAttachmentRecord { return nil }
func cleanupStaleAttachments([]ownedAttachmentRecord) error         { return nil }
