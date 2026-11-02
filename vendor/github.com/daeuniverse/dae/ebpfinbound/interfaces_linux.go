//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

// The janitor owns these states after startup. Its operation gate makes Close
// wait for reconciliation before releasing programs, namespaces or callbacks.
func (r *captureRuntime) attachManagedInterface(name string, wan bool, record func(ownedAttachmentRecord) error) ([]ownedTCAttachment, []func() error, error) {
	link, err := captureInterface(name)
	if err != nil {
		return nil, nil, err
	}
	state := &interfaceAttachment{index: link.Attrs().Index}
	if r.interfaceAttachments == nil {
		r.interfaceAttachments = make(map[string]*interfaceAttachment)
	}
	r.interfaceAttachments[name] = state
	state.records, state.cleanup, err = r.attachRoleLink(link, wan, record)
	return state.records, []func() error{state.close}, err
}

func (r *captureRuntime) attachRoleLink(link netlink.Link, wan bool, record func(ownedAttachmentRecord) error) ([]ownedTCAttachment, []func() error, error) {
	if wan {
		return r.attachWANLink(link, record)
	}
	return r.attachLANLink(link, record)
}

func (r *captureRuntime) reconcileInterfaces() {
	reconcile := func(name string, wan bool) {
		state := r.interfaceAttachments[name]
		if state == nil {
			return
		}
		err := r.reconcileInterface(name, wan, state)
		message := ""
		if err != nil {
			message = err.Error()
		}
		if message != "" && message != state.lastError && r.log != nil {
			r.log.Warn("restore capture interface", "interface", name, "error", err)
		}
		state.lastError = message
	}
	for _, name := range r.config.LANInterfaces {
		reconcile(name, false)
	}
	for _, name := range r.config.WANInterfaces {
		reconcile(name, true)
	}
}

func (r *captureRuntime) reconcileInterface(name string, wan bool, state *interfaceAttachment) error {
	link, err := captureInterface(name)
	if err != nil {
		if !isMissingNetlinkError(err) {
			return err
		}
		// Removing a link destroys its TC hooks. Drop the old callbacks rather
		// than retaining a growing list of dead interface incarnations.
		state.index, state.records, state.cleanup = 0, nil, nil
		return nil
	}
	if link.Attrs().Index == state.index {
		complete, err := interfaceAttachmentsPresent(link, state.records)
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		if err := state.close(); err != nil {
			return err
		}
	}
	state.index, state.records, state.cleanup = link.Attrs().Index, nil, nil
	if wan {
		err = r.configureWANInterface(name)
	} else {
		err = r.configureLANInterface(name)
	}
	if err != nil {
		return err
	}
	state.records, state.cleanup, err = r.attachRoleLink(link, wan, r.ownership.UpsertAttachment)
	if err != nil {
		return err
	}
	if r.log != nil {
		r.log.Info("restored capture interface", "interface", name, "index", state.index)
	}
	return nil
}

func interfaceAttachmentsPresent(link netlink.Link, records []ownedTCAttachment) (bool, error) {
	complete := len(records) == 2
	for _, attachment := range records {
		record := attachment.record
		filter, err := findTCFilter(link, record.Parent, record.Handle)
		if errors.Is(err, errTCFilterNotFound) {
			complete = false
			continue
		}
		if err != nil {
			return false, err
		}
		bpf, ok := filter.(*netlink.BpfFilter)
		if !ok || bpf.Name != record.Name || bpf.Id != record.ProgramID {
			return false, fmt.Errorf("refuse to replace TC filter on %s: ownership identity changed", link.Attrs().Name)
		}
	}
	return complete, nil
}
