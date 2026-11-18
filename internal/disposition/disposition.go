// Package disposition states what a person decided to do about a vulnerability
// instead of fixing it. A disposition is read beside the findings it covers and
// never folded into them: nothing that decides or keeps a finding names this
// package, so the platform goes on deciding whatever a person decided.
package disposition

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const SchemaVersion = 1

const (
	MaxReasonLength = 1024
	Longest         = 365 * 24 * time.Hour
)

var (
	ErrMalformed    = errors.New("the request does not describe a disposition the platform keeps")
	ErrNoActor      = errors.New("a disposition is attributable or it is not recorded")
	ErrUnregistered = errors.New("the disposition names an agent its tenant has not registered")
	ErrUnknown      = errors.New("no disposition was recorded under that id, or it is outside this caller's tenants")
	ErrLapsed       = errors.New("the disposition has lapsed: it expired or was withdrawn")
	ErrCursor       = errors.New("the cursor was not issued for this listing")
)

// The actor is whoever proved who they are on the connection and the instant is
// the platform's, so neither is read from what was asked.
func Record(asked *vulnerabilityv1.DispositionRequest, actor string, at time.Time) (*vulnerabilityv1.Disposition, error) {
	if actor == "" {
		return nil, ErrNoActor
	}
	switch {
	case !event.ValidIdentifier(asked.GetTenantId()):
		return nil, fmt.Errorf("%w: %s is not a usable tenant identifier", ErrMalformed, quoted(asked.GetTenantId()))
	case !vulnerability.Identifier(asked.GetVulnerabilityId()):
		return nil, fmt.Errorf("%w: %s names no vulnerability", ErrMalformed, quoted(asked.GetVulnerabilityId()))
	case asked.GetAgentId() != "" && !agentidentity.Valid(asked.GetAgentId()):
		return nil, fmt.Errorf("%w: %s is not a usable agent identifier", ErrMalformed, quoted(asked.GetAgentId()))
	case len(asked.GetPackageName()) > inventory.MaxNameLength:
		return nil, fmt.Errorf("%w: the package name is longer than %d bytes", ErrMalformed, inventory.MaxNameLength)
	case !utf8.ValidString(asked.GetPackageName()) || strings.IndexFunc(asked.GetPackageName(), unicode.IsControl) >= 0:
		return nil, fmt.Errorf("%w: the package name carries a control character", ErrMalformed)
	}
	kind, known := KindOf(asked.GetKind())
	if !known {
		return nil, fmt.Errorf("%w: %s is not a kind of disposition", ErrMalformed, asked.GetKind())
	}
	if err := explained("reason", asked.GetReason()); err != nil {
		return nil, err
	}

	decided := kept(at)
	expires, err := expiry(asked.GetExpiresAt(), decided)
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return &vulnerabilityv1.Disposition{
		DispositionId:   id,
		SchemaVersion:   SchemaVersion,
		TenantId:        asked.GetTenantId(),
		VulnerabilityId: asked.GetVulnerabilityId(),
		AgentId:         asked.GetAgentId(),
		PackageName:     asked.GetPackageName(),
		Kind:            kind.Wire(),
		Reason:          asked.GetReason(),
		Actor:           actor,
		DecidedAt:       timestamppb.New(decided),
		ExpiresAt:       timestamppb.New(expires),
	}, nil
}

// Ending a disposition early, asked by a person and timed by the platform.
type Withdrawal struct {
	Reason string
	Actor  string
	At     time.Time
}

// Withdrawing is written beside the disposition: the record of who decided what
// and for how long is never changed by ending it.
func Withdraw(held *vulnerabilityv1.Disposition, withdrawal Withdrawal) (*vulnerabilityv1.Disposition, error) {
	if withdrawal.Actor == "" {
		return nil, ErrNoActor
	}
	if err := explained("withdrawal reason", withdrawal.Reason); err != nil {
		return nil, err
	}
	withdrawn := kept(withdrawal.At)
	if !InForce(held, withdrawn) {
		return nil, fmt.Errorf("%w: %s", ErrLapsed, held.GetDispositionId())
	}

	changed, _ := proto.Clone(held).(*vulnerabilityv1.Disposition)
	changed.WithdrawnBy = withdrawal.Actor
	changed.WithdrawnAt = timestamppb.New(withdrawn)
	changed.WithdrawalReason = withdrawal.Reason
	return changed, nil
}

func InForce(held *vulnerabilityv1.Disposition, at time.Time) bool {
	return held.GetWithdrawnAt() == nil && at.Before(held.GetExpiresAt().AsTime())
}

func expiry(asked *timestamppb.Timestamp, decided time.Time) (time.Time, error) {
	if asked == nil {
		return time.Time{}, fmt.Errorf("%w: the expiry is required: a disposition that never lapses hides a vulnerability for good", ErrMalformed)
	}
	if !asked.IsValid() {
		return time.Time{}, fmt.Errorf("%w: the expiry is not an instant", ErrMalformed)
	}
	expires := kept(asked.AsTime())
	switch {
	case !expires.After(decided):
		return time.Time{}, fmt.Errorf("%w: the expiry is not after the moment the disposition is recorded", ErrMalformed)
	case expires.Sub(decided) > Longest:
		return time.Time{}, fmt.Errorf("%w: a disposition lasts %d days at most", ErrMalformed, Longest/(24*time.Hour))
	}
	return expires, nil
}

func explained(field, value string) error {
	switch {
	case strings.TrimSpace(value) == "":
		return fmt.Errorf("%w: the %s is required", ErrMalformed, field)
	case len(value) > MaxReasonLength:
		return fmt.Errorf("%w: the %s is longer than %d bytes", ErrMalformed, field, MaxReasonLength)
	case !utf8.ValidString(value) || strings.IndexFunc(value, unwritten) >= 0:
		return fmt.Errorf("%w: the %s carries a control character", ErrMalformed, field)
	}
	return nil
}

func unwritten(character rune) bool {
	return unicode.IsControl(character) && character != '\t' && character != '\n' && character != '\r'
}

func kept(at time.Time) time.Time { return at.UTC().Truncate(time.Microsecond) }

func quoted(value string) string { return strconv.Quote(value[:min(len(value), 64)]) }
