package agentupdate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	MaxRolloutAgents = 10000
	MaxWaves         = 16
	MaxCanaryAgents  = 100
	MaxRunning       = 10000
	MaxFailures      = 10000
	MinSoak          = time.Minute
	MaxSoak          = 30 * 24 * time.Hour

	// An agent's place in a rollout is one of this many, and a wave of
	// `percent` reaches the places below `percent` hundredths of them.
	Places = 10000

	// Who the platform records as having made a change its gates made.
	Platform = "platform"
)

var (
	ErrRolloutUnknown = errors.New("no such rollout is held in the tenant")
	ErrRolloutState   = errors.New("the rollout does not stand where that change applies")
	ErrRolloutCursor  = errors.New("the cursor was not issued for this listing")
)

type AcceptedRollout struct {
	Record *updatev1.RolloutRecord
}

func (a AcceptedRollout) ID() string { return a.Record.GetRolloutId() }

func (a AcceptedRollout) Rollout() *updatev1.Rollout { return a.Record.GetRollout() }

// Whether the newest catalog names the version and every agent is registered
// in the tenant is decided by the store, under the tenant's lock, together
// with which rollout this one takes over from.
func AcceptRollout(asked *updatev1.Rollout, actor string, at time.Time) (AcceptedRollout, error) {
	if err := attributable(actor, asked.GetNote()); err != nil {
		return AcceptedRollout{}, err
	}
	tenant := asked.GetTenantId()
	switch {
	case tenant == "" || len(tenant) > event.MaxTenantIDLength || !event.ValidIdentifier(tenant):
		return AcceptedRollout{}, fmt.Errorf("%w: %s is not a usable tenant identifier", ErrMalformed, strconv.Quote(bounded(tenant)))
	case len(asked.GetAgentIds()) > MaxRolloutAgents:
		return AcceptedRollout{}, fmt.Errorf("%w: a rollout names at most %d agents, and this one names %d",
			ErrMalformed, MaxRolloutAgents, len(asked.GetAgentIds()))
	case asked.GetFailures() == 0 || asked.GetFailures() > MaxFailures:
		return AcceptedRollout{}, fmt.Errorf("%w: between 1 and %d failing agents pause a rollout, and this one says %d",
			ErrMalformed, MaxFailures, asked.GetFailures())
	}
	if _, valid := ParseVersion(asked.GetVersion()); !valid {
		return AcceptedRollout{}, fmt.Errorf("%w: %s is not a semantic version with a leading v", ErrMalformed, strconv.Quote(bounded(asked.GetVersion())))
	}
	population, err := distinct("the rollout", asked.GetAgentIds())
	if err != nil {
		return AcceptedRollout{}, err
	}
	if err := validateWaves(asked.GetWaves(), population); err != nil {
		return AcceptedRollout{}, err
	}

	id, err := newRolloutID()
	if err != nil {
		return AcceptedRollout{}, err
	}
	taken, _ := proto.Clone(asked).(*updatev1.Rollout)
	stamp := timestamppb.New(at.UTC())
	return AcceptedRollout{Record: &updatev1.RolloutRecord{
		RolloutId:    id,
		Rollout:      taken,
		State:        updatev1.RolloutRecord_STATE_ACTIVE,
		WaveOpenedAt: stamp,
		CreatedBy:    actor,
		CreatedAt:    stamp,
		ChangedBy:    actor,
		ChangedAt:    stamp,
		Reason:       asked.GetNote(),
	}}, nil
}

func validateWaves(waves []*updatev1.Wave, population map[string]bool) error {
	if len(waves) == 0 || len(waves) > MaxWaves {
		return fmt.Errorf("%w: a rollout opens between 1 and %d waves, and this one opens %d", ErrMalformed, MaxWaves, len(waves))
	}
	reached := uint32(0)
	for index, wave := range waves {
		named := fmt.Sprintf("wave %d", index)
		last := index == len(waves)-1
		switch {
		case len(wave.GetAgentIds()) > 0 && wave.GetPercent() > 0:
			return fmt.Errorf("%w: %s both names agents and opens a share of them", ErrMalformed, named)
		case len(wave.GetAgentIds()) == 0 && wave.GetPercent() == 0:
			return fmt.Errorf("%w: %s neither names agents nor opens a share of them", ErrMalformed, named)
		case len(wave.GetAgentIds()) > MaxCanaryAgents:
			return fmt.Errorf("%w: %s names %d agents, and a wave names at most %d", ErrMalformed, named, len(wave.GetAgentIds()), MaxCanaryAgents)
		case wave.GetPercent() > 100 || (wave.GetPercent() > 0 && wave.GetPercent() <= reached):
			return fmt.Errorf("%w: %s opens %d percent, which is not more than %d and at most 100", ErrMalformed, named, wave.GetPercent(), reached)
		case last && wave.GetPercent() != 100:
			return fmt.Errorf("%w: the last wave opens the release to every agent of the rollout, at 100 percent", ErrMalformed)
		case last && (wave.GetSoak() != nil || wave.GetRunning() != 0):
			return fmt.Errorf("%w: nothing opens after the last wave, so it has no soak and requires nobody running", ErrMalformed)
		}
		reached = max(reached, wave.GetPercent())

		canaries, err := distinct(named, wave.GetAgentIds())
		if err != nil {
			return err
		}
		if len(population) > 0 {
			for id := range canaries {
				if !population[id] {
					return fmt.Errorf("%w: %s names agent %s, which the rollout does not", ErrMalformed, named, id)
				}
			}
		}

		if last {
			continue
		}
		soak := wave.GetSoak()
		switch {
		case soak == nil && wave.GetRunning() != 0:
			return fmt.Errorf("%w: %s waits for an operator, so it requires nobody running", ErrMalformed, named)
		case soak == nil:
		case !soak.IsValid() || soak.AsDuration() < MinSoak || soak.AsDuration() > MaxSoak:
			return fmt.Errorf("%w: %s soaks for between %s and %s", ErrMalformed, named, MinSoak, MaxSoak)
		case wave.GetRunning() == 0 || wave.GetRunning() > MaxRunning:
			return fmt.Errorf("%w: %s opens the next wave on its own once between 1 and %d agents run the release, and says %d",
				ErrMalformed, named, MaxRunning, wave.GetRunning())
		}
	}
	return nil
}

func distinct(what string, agents []string) (map[string]bool, error) {
	seen := make(map[string]bool, len(agents))
	for _, id := range agents {
		switch {
		case len(id) > event.MaxAgentIDLength || !event.ValidIdentifier(id):
			return nil, fmt.Errorf("%w: %s names %s, which is not a usable agent identifier", ErrMalformed, what, strconv.Quote(bounded(id)))
		case seen[id]:
			return nil, fmt.Errorf("%w: %s names agent %s twice", ErrMalformed, what, id)
		}
		seen[id] = true
	}
	return seen, nil
}

func newRolloutID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("draw a rollout identifier: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	text := hex.EncodeToString(id[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:], nil
}

// A rollout is named by the identifier the platform drew for it, written the
// one way it draws it.
func ValidRolloutID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, character := range id {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

// Place is where an agent stands in a rollout: decided by the rollout and the
// agent alone, so nothing the agent does between two requests moves it.
func Place(rolloutID, agentID string) uint32 {
	digest := sha256.New()
	digest.Write([]byte(rolloutID))
	digest.Write([]byte{0})
	digest.Write([]byte(agentID))
	return uint32(binary.BigEndian.Uint64(digest.Sum(nil)[:8]) % Places)
}

// Reaches says whether the waves opened so far reach an agent of the rollout.
func Reaches(rolloutID string, rollout *updatev1.Rollout, opened uint32, agentID string) bool {
	waves := rollout.GetWaves()
	if len(waves) == 0 {
		return false
	}
	share := uint32(0)
	for _, wave := range waves[:min(int(opened)+1, len(waves))] {
		if slices.Contains(wave.GetAgentIds(), agentID) {
			return true
		}
		share = max(share, wave.GetPercent())
	}
	return share > 0 && Place(rolloutID, agentID) < share*(Places/100)
}

// The version a rollout in force asks one agent to run: its release while it
// is active and an open wave reaches the agent, and nothing otherwise, so the
// agent keeps the release it runs.
func Offered(record *updatev1.RolloutRecord, member bool, agentID string) string {
	if record == nil || !member || record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		return ""
	}
	if !Reaches(record.GetRolloutId(), record.GetRollout(), record.GetWave(), agentID) {
		return ""
	}
	return record.GetRollout().GetVersion()
}

// Wanted is the release the platform asks an agent to run: the one assigned to
// it one by one, whatever its tenant's rollout says, or else the one that
// rollout asks of it.
func Wanted(assigned string, rollout *updatev1.RolloutRecord, member bool, agentID string) string {
	if assigned != "" {
		return assigned
	}
	return Offered(rollout, member, agentID)
}

type AcceptedChange struct {
	TenantID  string
	RolloutID string
	Action    updatev1.RolloutChange_Action
	Actor     string
	At        time.Time
	Note      string
}

func AcceptChange(asked *updatev1.RolloutChange, actor string, at time.Time) (AcceptedChange, error) {
	if err := attributable(actor, asked.GetNote()); err != nil {
		return AcceptedChange{}, err
	}
	switch {
	case !event.ValidIdentifier(asked.GetTenantId()):
		return AcceptedChange{}, fmt.Errorf("%w: %s is not a usable tenant identifier", ErrMalformed, strconv.Quote(bounded(asked.GetTenantId())))
	case !ValidRolloutID(asked.GetRolloutId()):
		return AcceptedChange{}, fmt.Errorf("%w: %s", ErrRolloutUnknown, strconv.Quote(bounded(asked.GetRolloutId())))
	}
	if _, declared := updatev1.RolloutChange_Action_name[int32(asked.GetAction())]; !declared || asked.GetAction() == updatev1.RolloutChange_ACTION_UNSPECIFIED {
		return AcceptedChange{}, fmt.Errorf("%w: a change pauses, resumes, advances or aborts a rollout", ErrMalformed)
	}
	return AcceptedChange{
		TenantID:  asked.GetTenantId(),
		RolloutID: asked.GetRolloutId(),
		Action:    asked.GetAction(),
		Actor:     actor,
		At:        at.UTC(),
		Note:      asked.GetNote(),
	}, nil
}

// What a change makes of a rollout as it stands, or why it does not apply, and
// whether it resumed the rollout: a resumed rollout takes the agents last read
// as failing as known, so they no longer pause it.
func (c AcceptedChange) Apply(held *updatev1.RolloutRecord) (*updatev1.RolloutRecord, bool, error) {
	changed, _ := proto.Clone(held).(*updatev1.RolloutRecord)
	state, acknowledge := held.GetState(), false
	switch c.Action {
	case updatev1.RolloutChange_ACTION_PAUSE:
		if state != updatev1.RolloutRecord_STATE_ACTIVE {
			return nil, false, fmt.Errorf("%w: only an active rollout pauses, and this one is %s", ErrRolloutState, StateName(state))
		}
		changed.State = updatev1.RolloutRecord_STATE_PAUSED
	case updatev1.RolloutChange_ACTION_RESUME:
		if state != updatev1.RolloutRecord_STATE_PAUSED {
			return nil, false, fmt.Errorf("%w: only a paused rollout resumes, and this one is %s", ErrRolloutState, StateName(state))
		}
		changed.State, acknowledge = updatev1.RolloutRecord_STATE_ACTIVE, true
	case updatev1.RolloutChange_ACTION_ADVANCE:
		if state != updatev1.RolloutRecord_STATE_ACTIVE {
			return nil, false, fmt.Errorf("%w: only an active rollout advances, and this one is %s", ErrRolloutState, StateName(state))
		}
		if int(held.GetWave())+1 >= len(held.GetRollout().GetWaves()) {
			return nil, false, fmt.Errorf("%w: every wave of the rollout is open", ErrRolloutState)
		}
		changed.Wave, changed.WaveOpenedAt = held.GetWave()+1, timestamppb.New(c.At)
	case updatev1.RolloutChange_ACTION_ABORT:
		if state != updatev1.RolloutRecord_STATE_ACTIVE && state != updatev1.RolloutRecord_STATE_PAUSED {
			return nil, false, fmt.Errorf("%w: only a rollout in force is aborted, and this one is %s", ErrRolloutState, StateName(state))
		}
		changed.State = updatev1.RolloutRecord_STATE_ABORTED
	}
	changed.ChangedBy, changed.ChangedAt, changed.Reason = c.Actor, timestamppb.New(c.At), c.Note
	return changed, acknowledge, nil
}

func StateName(state updatev1.RolloutRecord_State) string {
	switch state {
	case updatev1.RolloutRecord_STATE_ACTIVE:
		return "active"
	case updatev1.RolloutRecord_STATE_PAUSED:
		return "paused"
	case updatev1.RolloutRecord_STATE_ABORTED:
		return "aborted"
	case updatev1.RolloutRecord_STATE_SUPERSEDED:
		return "superseded"
	}
	return "unspecified"
}

func ParseState(name string) (updatev1.RolloutRecord_State, bool) {
	for _, state := range []updatev1.RolloutRecord_State{
		updatev1.RolloutRecord_STATE_ACTIVE, updatev1.RolloutRecord_STATE_PAUSED,
		updatev1.RolloutRecord_STATE_ABORTED, updatev1.RolloutRecord_STATE_SUPERSEDED,
	} {
		if StateName(state) == name {
			return state, true
		}
	}
	return updatev1.RolloutRecord_STATE_UNSPECIFIED, false
}

// A rollout in force is one that still decides what agents are asked to run.
func InForce(state updatev1.RolloutRecord_State) bool {
	return state == updatev1.RolloutRecord_STATE_ACTIVE || state == updatev1.RolloutRecord_STATE_PAUSED
}

// A rollout in force as the store holds it: its record, without the agents it
// names one by one, whether it names any, and how many times its state or its
// wave changed.
type Held struct {
	Record  *updatev1.RolloutRecord
	Named   bool
	Changes int64
}

// The agents of a rollout the platform still listens to, those of them
// assigned a release one by one, and those whose failure is known.
type Reach struct {
	Agents       []string
	Pinned       map[string]bool
	Acknowledged map[string]bool
}

// What one reading of a rollout settled: the record with its progress and,
// when a gate moved it, its new state or wave, and the agents it read as
// failing, which an operator resuming the rollout takes as known.
type Settled struct {
	Held    Held
	Record  *updatev1.RolloutRecord
	Moved   bool
	Failing []string
}
