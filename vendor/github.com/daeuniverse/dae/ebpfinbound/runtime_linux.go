//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf/rlimit"
)

type operationGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	closing bool
	active  int
}

func (g *operationGate) init() { g.cond = sync.NewCond(&g.mu) }
func (g *operationGate) enter() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return net.ErrClosed
	}
	g.active++
	return nil
}
func (g *operationGate) leave() {
	g.mu.Lock()
	g.active--
	if g.active == 0 && g.cond != nil {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}
func (g *operationGate) closeAndWait() {
	g.mu.Lock()
	g.closing = true
	for g.active != 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

type captureRuntime struct {
	config CaptureConfig
	log    *slog.Logger

	gate operationGate

	stateMu                sync.RWMutex
	ready                  bool
	processMetadataEnabled bool
	listeners              *listenerSet
	ownership              *ownershipLease
	netns                  *captureNetNS
	bpf                    *captureObjects
	detachFunctions        []func() error
	publishedFiles         []*os.File

	lifecycle   context.Context
	cancel      context.CancelFunc
	janitorDone chan struct{}

	closeOnce sync.Once
	closeErr  error
}

var _ Runtime = (*captureRuntime)(nil)

// New creates and fully activates a one-shot capture runtime. It returns only
// after transparent listeners have been published and every required traffic
// hook is attached. Any startup failure destroys the incomplete BPF collection
// and every resource created by this call.
func New(ctx context.Context, options Options) (_ Runtime, returnErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("dae eBPF inbound requires root privileges")
	}
	config, report, err := ResolveConfig(ctx, options.Capture)
	if err != nil {
		return nil, err
	}
	if !config.AutoConfigureKernel && len(report.KernelProblems) != 0 {
		return nil, fmt.Errorf("automatic kernel configuration is disabled: %v", report.KernelProblems)
	}
	logger, err := options.logger()
	if err != nil {
		return nil, err
	}
	ownership, err := acquireOwnership(report)
	if err != nil {
		return nil, err
	}
	cleanupOwnership := true
	var startupCleanupErr error
	defer func() {
		if cleanupOwnership {
			var releaseErr error
			if startupCleanupErr == nil {
				releaseErr = ownership.Close()
			} else {
				releaseErr = ownership.Abandon()
			}
			returnErr = errors.Join(returnErr, startupCleanupErr, releaseErr)
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	ns, err := newCaptureNetNS(ctx, logger, ownership)
	cleanupNS := ns != nil
	defer func() {
		if cleanupNS && ns != nil {
			startupCleanupErr = errors.Join(startupCleanupErr, ns.Close())
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("set up capture network namespace: %w", err)
	}
	objects, err := loadCaptureBPF(ns, config)
	if err != nil {
		return nil, fmt.Errorf("load capture BPF objects: %w", err)
	}
	cleanupBPF := true
	defer func() {
		if cleanupBPF {
			startupCleanupErr = errors.Join(startupCleanupErr, objects.Close())
		}
	}()

	var listeners *listenerSet
	if err := ns.With(func() error {
		var openErr error
		listeners, openErr = openListenerSet(ctx, config.TProxyPort, logger)
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("open transparent listeners: %w", err)
	}
	cleanupListeners := true
	defer func() {
		if cleanupListeners {
			startupCleanupErr = errors.Join(startupCleanupErr, listeners.close())
		}
	}()
	publishedFiles, err := publishListenersOnce(objects, listeners)
	if err != nil {
		return nil, fmt.Errorf("publish transparent listeners: %w", err)
	}
	cleanupFiles := true
	defer func() {
		if cleanupFiles {
			for _, file := range publishedFiles {
				if file != nil {
					startupCleanupErr = errors.Join(startupCleanupErr, file.Close())
				}
			}
		}
	}()

	lifecycle, cancel := context.WithCancel(context.Background())
	runtime := &captureRuntime{
		config:         config,
		log:            logger,
		listeners:      listeners,
		ownership:      ownership,
		netns:          ns,
		bpf:            objects,
		publishedFiles: publishedFiles,
		lifecycle:      lifecycle,
		cancel:         cancel,
		janitorDone:    make(chan struct{}),
	}
	runtime.gate.init()
	cleanupAttachments := true
	defer func() {
		if cleanupAttachments {
			startupCleanupErr = errors.Join(startupCleanupErr, runCleanupReverse(runtime.detachFunctions))
		}
	}()
	attachments, detachFunctions, err := runtime.attachDatapath()
	runtime.detachFunctions = detachFunctions
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ownership.SetAttachments(attachmentRecords(attachments)); err != nil {
		cancel()
		return nil, fmt.Errorf("record attached traffic hooks: %w", err)
	}
	runtime.stateMu.Lock()
	runtime.ready = true
	runtime.stateMu.Unlock()
	go runtime.runJanitor()

	cleanupOwnership = false
	cleanupNS = false
	cleanupBPF = false
	cleanupListeners = false
	cleanupFiles = false
	cleanupAttachments = false
	logger.Info("started standalone dae eBPF capture runtime",
		"lan_interfaces", config.LANInterfaces,
		"wan_interfaces", config.WANInterfaces,
		"output_mark", fmt.Sprintf("%#x", config.OutputMark),
		"port", config.TProxyPort,
	)
	return runtime, nil
}

func (r *captureRuntime) Listeners() ListenerSet {
	if r == nil {
		return nil
	}
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.listeners
}

func (r *captureRuntime) LookupMetadata(ctx context.Context, flow Flow) (Metadata, bool, error) {
	if r == nil {
		return Metadata{}, false, net.ErrClosed
	}
	if err := flow.Validate(); err != nil {
		return Metadata{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Metadata{}, false, err
	}
	if err := r.gate.enter(); err != nil {
		return Metadata{}, false, err
	}
	defer r.gate.leave()
	r.stateMu.RLock()
	objects := r.bpf
	ready := r.ready
	r.stateMu.RUnlock()
	if !ready || objects == nil {
		return Metadata{}, false, net.ErrClosed
	}
	return lookupFlowMetadata(ctx, objects, flow)
}

func (r *captureRuntime) OutputMark() uint32 {
	if r == nil {
		return 0
	}
	return r.config.OutputMark
}

func (r *captureRuntime) Status() Status {
	if r == nil {
		return Status{}
	}
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return Status{
		Ready:                  r.ready,
		LANInterfaces:          append([]string(nil), r.config.LANInterfaces...),
		WANInterfaces:          append([]string(nil), r.config.WANInterfaces...),
		ProcessMetadataEnabled: r.processMetadataEnabled,
		OutputMark:             r.config.OutputMark,
		Port:                   r.config.TProxyPort,
	}
}

func (r *captureRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() { r.closeErr = r.close() })
	return r.closeErr
}

func (r *captureRuntime) close() error {
	r.gate.closeAndWait()
	r.stateMu.Lock()
	if !r.ready && r.bpf == nil && r.netns == nil && r.ownership == nil {
		r.stateMu.Unlock()
		return nil
	}
	r.ready = false
	if r.cancel != nil {
		r.cancel()
	}
	janitorDone := r.janitorDone
	detachFunctions := r.detachFunctions
	r.detachFunctions = nil
	listeners := r.listeners
	r.listeners = nil
	publishedFiles := r.publishedFiles
	r.publishedFiles = nil
	objects := r.bpf
	r.bpf = nil
	ns := r.netns
	r.netns = nil
	ownership := r.ownership
	r.ownership = nil
	r.stateMu.Unlock()

	if janitorDone != nil {
		<-janitorDone
	}
	var errs []error
	if err := runCleanupReverse(detachFunctions); err != nil {
		errs = append(errs, err)
	}
	if listeners != nil {
		if err := listeners.close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, file := range publishedFiles {
		if file != nil {
			if err := file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if objects != nil {
		if err := objects.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if ns != nil {
		if err := ns.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if ownership != nil {
		resourceErr := errors.Join(errs...)
		if resourceErr == nil {
			if err := ownership.Close(); err != nil {
				errs = append(errs, err)
			}
		} else if err := ownership.Abandon(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func runCleanupReverse(functions []func() error) error {
	var errs []error
	for index := len(functions) - 1; index >= 0; index-- {
		if functions[index] == nil {
			continue
		}
		if err := functions[index](); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
