package agent_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func identity() *agentv1.Identity {
	return &agentv1.Identity{
		Subject:           "web-01",
		Serial:            "3fa10b7c9d2e4f61",
		FingerprintSha256: strings.Repeat("ab", 32),
		IssuedAt:          timestamppb.New(registered),
		ExpiresAt:         timestamppb.New(registered.Add(90 * 24 * time.Hour)),
	}
}

func TestACertificateIsBoundOnlyToTheAgentItNames(t *testing.T) {
	if err := agent.Bindable("web-01", identity(), registered); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	somebodyElse := identity()
	somebodyElse.Subject = "db-07"
	err := agent.Bindable("web-01", somebodyElse, registered)
	if !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("a certificate naming another agent was bound: %v", err)
	}
}

func TestAnIdentityThatCannotBeMatchedIsRefused(t *testing.T) {
	cases := map[string]func(*agentv1.Identity){
		"no serial":            func(i *agentv1.Identity) { i.Serial = "" },
		"unreadable serial":    func(i *agentv1.Identity) { i.Serial = "not-a-serial" },
		"oversize serial":      func(i *agentv1.Identity) { i.Serial = strings.Repeat("a", 70) },
		"short fingerprint":    func(i *agentv1.Identity) { i.FingerprintSha256 = strings.Repeat("ab", 16) },
		"upper fingerprint":    func(i *agentv1.Identity) { i.FingerprintSha256 = strings.Repeat("AB", 32) },
		"unreadable fingerpr.": func(i *agentv1.Identity) { i.FingerprintSha256 = strings.Repeat("zz", 32) },
		"no expiry":            func(i *agentv1.Identity) { i.ExpiresAt = nil },
	}
	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			held := identity()
			broken(held)
			if err := agent.Bindable("web-01", held, registered); !errors.Is(err, agent.ErrMalformedIdentity) {
				t.Fatalf("expected a malformed identity, got %v", err)
			}
		})
	}
	if err := agent.Bindable("web-01", nil, registered); !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("an absent identity was bound: %v", err)
	}
}

func TestAnIdentityIsNotBoundAfterItHasExpired(t *testing.T) {
	held := identity()
	err := agent.Bindable("web-01", held, held.GetExpiresAt().AsTime().Add(time.Second))
	if !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("an expired certificate was bound: %v", err)
	}

	backwards := identity()
	backwards.ExpiresAt = timestamppb.New(registered.Add(-time.Hour))
	if err := agent.Bindable("web-01", backwards, registered); !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("a certificate expiring before it was issued was bound: %v", err)
	}
}
