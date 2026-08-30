package socks

import (
	"errors"
	"testing"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
)

type testCredentialProvider struct {
	verifier auth.Verifier
	err      error
}

func (p *testCredentialProvider) Verifier(M.Socksaddr) (auth.Verifier, error) {
	return p.verifier, p.err
}

func TestSetCredentialProvider(t *testing.T) {
	inbound := new(Inbound)
	provider := &testCredentialProvider{verifier: auth.NewAuthenticator([]auth.User{
		{Username: "egress-a", Password: "client-a"},
		{Username: "egress-a", Password: "client-b"},
	})}
	if err := inbound.SetCredentialProvider(provider); err != nil {
		t.Fatal(err)
	}
	verifier, err := inbound.credentialProvider.Load().provider.Verifier(M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify("egress-a", "client-a") || !verifier.Verify("egress-a", "client-b") {
		t.Fatal("provider did not preserve multiple credentials for one auth_user")
	}
}

func TestSetCredentialProviderOnce(t *testing.T) {
	inbound := new(Inbound)
	first := &testCredentialProvider{verifier: auth.NewAuthenticator([]auth.User{{Username: "a", Password: "a"}})}
	second := &testCredentialProvider{verifier: auth.NewAuthenticator([]auth.User{{Username: "b", Password: "b"}})}
	if err := inbound.SetCredentialProvider(first); err != nil {
		t.Fatal(err)
	}
	if err := inbound.SetCredentialProvider(second); err == nil {
		t.Fatal("credential provider was replaceable at runtime")
	}
	if inbound.credentialProvider.Load().provider != first {
		t.Fatal("rejected replacement changed the provider")
	}
}

func TestCredentialProviderCanFailClosed(t *testing.T) {
	inbound := new(Inbound)
	provider := &testCredentialProvider{err: errors.New("snapshot unavailable")}
	if err := inbound.SetCredentialProvider(provider); err != nil {
		t.Fatal(err)
	}
	verifier, err := inbound.credentialProvider.Load().provider.Verifier(M.Socksaddr{})
	if err == nil || verifier != nil {
		t.Fatal("unavailable snapshot did not fail closed")
	}
}
