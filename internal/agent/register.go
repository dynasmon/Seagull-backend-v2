package agent

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	MaxNoteLength    = 512
	MaxVersionLength = 64
)

var (
	ErrMalformed  = errors.New("the registration does not describe a usable agent")
	ErrRegistered = errors.New("an agent is already registered under that identifier")
	ErrUnknown    = errors.New("no agent is registered under that identifier, or it is outside this caller's tenants")
	ErrCursor     = errors.New("the cursor was not issued for this listing")
	ErrConflict   = errors.New("one revision of an agent was published deciding two different things")
)

// The identifier an agent is registered under is the one a certificate may
// carry, checked against the same rule the gateway reads a connection with: a
// registry that accepted an identifier the gateway cannot read would hold
// records nothing could ever match.
func Register(asked *agentv1.Registration, actor string, at time.Time) (*agentv1.Agent, *agentv1.Transition, error) {
	if actor == "" {
		return nil, nil, ErrNoActor
	}
	if !agentidentity.Valid(asked.GetAgentId()) {
		return nil, nil, fmt.Errorf("%w: %q is not a usable agent identifier", ErrMalformed, asked.GetAgentId())
	}
	if err := tenant(asked.GetTenantId()); err != nil {
		return nil, nil, err
	}
	if err := within("agent_version", asked.GetAgentVersion(), MaxVersionLength); err != nil {
		return nil, nil, err
	}
	if err := within("note", asked.GetNote(), MaxNoteLength); err != nil {
		return nil, nil, err
	}
	if err := platform(asked.GetPlatform()); err != nil {
		return nil, nil, err
	}

	stamp := timestamppb.New(at.UTC())
	registered := &agentv1.Agent{
		AgentId:       asked.GetAgentId(),
		SchemaVersion: SchemaVersion,
		TenantId:      asked.GetTenantId(),
		State:         Pending.Wire(),
		Platform:      asked.GetPlatform(),
		AgentVersion:  asked.GetAgentVersion(),
		RegisteredAt:  stamp,
		ChangedBy:     actor,
		ChangedAt:     stamp,
		Revision:      1,
	}
	return registered, &agentv1.Transition{
		AgentId:  registered.GetAgentId(),
		Revision: registered.GetRevision(),
		To:       registered.GetState(),
		Actor:    actor,
		At:       stamp,
		Note:     asked.GetNote(),
	}, nil
}

func tenant(value string) error {
	if value == "" {
		return fmt.Errorf("%w: an agent belongs to a tenant", ErrMalformed)
	}
	if len(value) > event.MaxTenantIDLength || !event.ValidIdentifier(value) {
		return fmt.Errorf("%w: %q is not a usable tenant identifier", ErrMalformed, value)
	}
	return nil
}

func platform(declared *agentv1.Platform) error {
	if err := within("platform.os", declared.GetOs(), event.MaxOperatingSystem); err != nil {
		return err
	}
	if err := within("platform.architecture", declared.GetArchitecture(), event.MaxArchitectureLen); err != nil {
		return err
	}
	return within("platform.hostname", declared.GetHostname(), event.MaxHostnameLength)
}

func within(field, value string, maximum int) error {
	if len(value) > maximum {
		return fmt.Errorf("%w: %s is longer than %d bytes", ErrMalformed, field, maximum)
	}
	return nil
}
