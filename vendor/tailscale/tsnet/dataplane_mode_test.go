package tsnet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/tailscale/net/tstun"
)

func TestResolvedDataPlaneMode(t *testing.T) {
	customTun := tstun.NewFake()
	tests := []struct {
		name    string
		server  *Server
		want    DataPlaneMode
		wantErr bool
	}{
		{name: "auto userspace", server: &Server{}, want: DataPlaneUserspace},
		{name: "auto custom tun", server: &Server{Tun: customTun}, want: DataPlaneSystemServices},
		{name: "explicit userspace", server: &Server{DataPlaneMode: DataPlaneUserspace}, want: DataPlaneUserspace},
		{name: "explicit system services", server: &Server{Tun: customTun, DataPlaneMode: DataPlaneSystemServices}, want: DataPlaneSystemServices},
		{name: "explicit pure system", server: &Server{Tun: customTun, DataPlaneMode: DataPlaneSystem}, want: DataPlaneSystem},
		{name: "userspace with custom tun", server: &Server{Tun: customTun, DataPlaneMode: DataPlaneUserspace}, wantErr: true},
		{name: "system without custom tun", server: &Server{DataPlaneMode: DataPlaneSystem}, wantErr: true},
		{name: "unknown", server: &Server{DataPlaneMode: DataPlaneMode(255)}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.server.resolvedDataPlaneMode()
			if (err != nil) != test.wantErr {
				t.Fatalf("resolvedDataPlaneMode() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("resolvedDataPlaneMode() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPureSystemDialRequiresExplicitDataPlaneDialer(t *testing.T) {
	server := &Server{}
	_, err := server.dialDataPlane(context.Background(), DataPlaneSystem, "tcp", "100.64.0.1:443")
	if !errors.Is(err, ErrDataPlaneDialerUnavailable) {
		t.Fatalf("dial error = %v, want %v", err, ErrDataPlaneDialerUnavailable)
	}

	sentinel := errors.New("data-plane dial called")
	var gotNetwork, gotAddress string
	server.DataPlaneDial = func(_ context.Context, network, address string) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		return nil, sentinel
	}
	_, err = server.dialDataPlane(context.Background(), DataPlaneSystem, "tcp6", "[fd7a:115c:a1e0::1]:8443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("dial error = %v, want callback error %v", err, sentinel)
	}
	if gotNetwork != "tcp6" || gotAddress != "[fd7a:115c:a1e0::1]:8443" {
		t.Fatalf("callback arguments = (%q, %q)", gotNetwork, gotAddress)
	}
}

func TestPureSystemListenServiceRequiresNetstack(t *testing.T) {
	server := &Server{
		Tun:           tstun.NewFake(),
		DataPlaneMode: DataPlaneSystem,
	}
	_, err := server.ListenService("svc:test", ServiceModeTCP{Port: 443})
	if !errors.Is(err, ErrNetstackDisabled) {
		t.Fatalf("ListenService error = %v, want %v", err, ErrNetstackDisabled)
	}
}
