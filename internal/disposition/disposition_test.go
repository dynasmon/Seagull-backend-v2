package disposition_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 123456789, time.UTC)

const day = 24 * time.Hour

func asked() *vulnerabilityv1.DispositionRequest {
	return &vulnerabilityv1.DispositionRequest{
		TenantId:        "default",
		VulnerabilityId: "CVE-2026-0001",
		AgentId:         "web-01",
		PackageName:     "openssl",
		Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK,
		Reason:          "the WAF blocks the vulnerable path until 3.0.15 ships",
		ExpiresAt:       timestamppb.New(now.Add(90 * day)),
	}
}

func recorded(t *testing.T) *vulnerabilityv1.Disposition {
	t.Helper()
	made, err := disposition.Record(asked(), "dev-responder", now)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	return made
}

func TestADispositionIsRecordedAsAskedByWhoeverAskedAndWhenToTheMicrosecond(t *testing.T) {
	made := recorded(t)

	want := &vulnerabilityv1.Disposition{
		DispositionId:   made.GetDispositionId(),
		SchemaVersion:   1,
		TenantId:        "default",
		VulnerabilityId: "CVE-2026-0001",
		AgentId:         "web-01",
		PackageName:     "openssl",
		Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK,
		Reason:          "the WAF blocks the vulnerable path until 3.0.15 ships",
		Actor:           "dev-responder",
		DecidedAt:       timestamppb.New(time.Date(2026, 11, 17, 12, 0, 0, 123456000, time.UTC)),
		ExpiresAt:       timestamppb.New(time.Date(2027, 2, 15, 12, 0, 0, 123456000, time.UTC)),
	}
	if !proto.Equal(made, want) {
		t.Errorf("recorded\n%v\nwant\n%v", made, want)
	}
	if !disposition.ValidID(made.GetDispositionId()) {
		t.Errorf("the disposition is named %q, which is not how the platform names one", made.GetDispositionId())
	}
}

func TestTwoDispositionsAskedAlikeAreNamedApart(t *testing.T) {
	first, second := recorded(t), recorded(t)
	if first.GetDispositionId() == second.GetDispositionId() {
		t.Errorf("two dispositions were both named %q", first.GetDispositionId())
	}
}

func TestADispositionNarrowedToNothingCoversTheWholeTenant(t *testing.T) {
	request := asked()
	request.AgentId, request.PackageName = "", ""
	request.Kind = vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED

	made, err := disposition.Record(request, "dev-responder", now)
	if err != nil {
		t.Fatalf("a disposition for every asset of a tenant was refused: %v", err)
	}
	if made.GetAgentId() != "" || made.GetPackageName() != "" || made.GetKind() != vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED {
		t.Errorf("recorded %v", made)
	}
}

func TestAReasonMaySpanLinesAndBeIndented(t *testing.T) {
	request := asked()
	request.Reason = "risk accepted by the board\r\nticket SEC-12\n\tuntil the appliance is retired"
	if _, err := disposition.Record(request, "dev-responder", now); err != nil {
		t.Errorf("a reason written over several lines was refused: %v", err)
	}
}

func TestADispositionLastsAYearAtMost(t *testing.T) {
	request := asked()
	request.ExpiresAt = timestamppb.New(now.Add(365 * day))
	if _, err := disposition.Record(request, "dev-responder", now); err != nil {
		t.Errorf("a disposition lasting a year was refused: %v", err)
	}

	request.ExpiresAt = timestamppb.New(now.Add(365*day + time.Microsecond))
	if _, err := disposition.Record(request, "dev-responder", now); !errors.Is(err, disposition.ErrMalformed) {
		t.Errorf("a disposition lasting a year and a microsecond was answered %v", err)
	}
}

func TestARequestTheDispositionContractRefusesIsNotRecorded(t *testing.T) {
	for name, change := range map[string]func(*vulnerabilityv1.DispositionRequest){
		"no tenant":                                 func(r *vulnerabilityv1.DispositionRequest) { r.TenantId = "" },
		"a tenant no binding could name":            func(r *vulnerabilityv1.DispositionRequest) { r.TenantId = "acme corp" },
		"no vulnerability":                          func(r *vulnerabilityv1.DispositionRequest) { r.VulnerabilityId = "" },
		"a vulnerability no advisory could name":    func(r *vulnerabilityv1.DispositionRequest) { r.VulnerabilityId = "CVE 2026 0001" },
		"an agent no certificate could carry":       func(r *vulnerabilityv1.DispositionRequest) { r.AgentId = "web 01" },
		"a package longer than any inventory names": func(r *vulnerabilityv1.DispositionRequest) { r.PackageName = strings.Repeat("a", 257) },
		"a package with a control character":        func(r *vulnerabilityv1.DispositionRequest) { r.PackageName = "openssl\x1b[2J" },
		"no kind": func(r *vulnerabilityv1.DispositionRequest) {
			r.Kind = vulnerabilityv1.DispositionKind_DISPOSITION_KIND_UNSPECIFIED
		},
		"a kind the contract does not declare": func(r *vulnerabilityv1.DispositionRequest) { r.Kind = 9 },
		"no reason":                            func(r *vulnerabilityv1.DispositionRequest) { r.Reason = "" },
		"a reason of blanks":                   func(r *vulnerabilityv1.DispositionRequest) { r.Reason = " \t\n " },
		"a reason longer than a kibibyte":      func(r *vulnerabilityv1.DispositionRequest) { r.Reason = strings.Repeat("a", 1025) },
		"a reason carrying a NUL":              func(r *vulnerabilityv1.DispositionRequest) { r.Reason = "accepted\x00" },
		"a reason carrying an escape sequence": func(r *vulnerabilityv1.DispositionRequest) { r.Reason = "accepted\x1b]0;owned\x07" },
		"a reason carrying a C1 control":       func(r *vulnerabilityv1.DispositionRequest) { r.Reason = "accepted\u009b2J" },
		"no expiry":                            func(r *vulnerabilityv1.DispositionRequest) { r.ExpiresAt = nil },
		"an expiry that is no instant": func(r *vulnerabilityv1.DispositionRequest) {
			r.ExpiresAt = &timestamppb.Timestamp{Seconds: now.Unix(), Nanos: -1}
		},
		"an expiry already past": func(r *vulnerabilityv1.DispositionRequest) {
			r.ExpiresAt = timestamppb.New(now.Add(-time.Second))
		},
		"an expiry the moment it is recorded": func(r *vulnerabilityv1.DispositionRequest) {
			r.ExpiresAt = timestamppb.New(now)
		},
		"an expiry inside the microsecond it is recorded in": func(r *vulnerabilityv1.DispositionRequest) {
			r.ExpiresAt = timestamppb.New(now.Add(100 * time.Nanosecond))
		},
	} {
		request := asked()
		change(request)
		if made, err := disposition.Record(request, "dev-responder", now); !errors.Is(err, disposition.ErrMalformed) {
			t.Errorf("%s: answered %v, %v", name, made, err)
		}
	}
}

func TestADispositionNobodyAskedForIsNotRecorded(t *testing.T) {
	if made, err := disposition.Record(asked(), "", now); !errors.Is(err, disposition.ErrNoActor) {
		t.Errorf("a disposition without an actor was answered %v, %v", made, err)
	}
}

func TestAWithdrawalIsANewFactAndLeavesWhatWasRecorded(t *testing.T) {
	made := recorded(t)
	before := proto.Clone(made)

	withdrawn, err := disposition.Withdraw(made, disposition.Withdrawal{
		Reason: "3.0.15 is installed everywhere", Actor: "dev-admin", At: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	want := proto.Clone(before).(*vulnerabilityv1.Disposition)
	want.WithdrawnBy = "dev-admin"
	want.WithdrawnAt = timestamppb.New(time.Date(2026, 11, 17, 13, 0, 0, 123456000, time.UTC))
	want.WithdrawalReason = "3.0.15 is installed everywhere"
	if !proto.Equal(withdrawn, want) {
		t.Errorf("withdrawn\n%v\nwant\n%v", withdrawn, want)
	}
	if !proto.Equal(made, before) {
		t.Errorf("withdrawing changed the disposition it was asked of: %v", made)
	}
}

func TestOnlyADispositionInForceIsWithdrawn(t *testing.T) {
	made := recorded(t)
	withdrawal := disposition.Withdrawal{Reason: "no longer needed", Actor: "dev-admin", At: now.Add(time.Hour)}

	withdrawn, err := disposition.Withdraw(made, withdrawal)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	withdrawal.At = now.Add(2 * time.Hour)
	if again, err := disposition.Withdraw(withdrawn, withdrawal); !errors.Is(err, disposition.ErrLapsed) {
		t.Errorf("a withdrawn disposition was withdrawn again: %v, %v", again, err)
	}
	withdrawal.At = made.GetExpiresAt().AsTime()
	if late, err := disposition.Withdraw(made, withdrawal); !errors.Is(err, disposition.ErrLapsed) {
		t.Errorf("a disposition was withdrawn the moment it expired: %v, %v", late, err)
	}
}

func TestAWithdrawalIsExplainedByWhoeverAsksForIt(t *testing.T) {
	made := recorded(t)
	for name, reason := range map[string]string{
		"no reason":                       "",
		"a reason of blanks":              "  \n",
		"a reason longer than a kibibyte": strings.Repeat("a", 1025),
		"a reason carrying an escape":     "done\x1b[0m",
	} {
		if withdrawn, err := disposition.Withdraw(made, disposition.Withdrawal{Reason: reason, Actor: "dev-admin", At: now}); !errors.Is(err, disposition.ErrMalformed) {
			t.Errorf("%s: answered %v, %v", name, withdrawn, err)
		}
	}
	if withdrawn, err := disposition.Withdraw(made, disposition.Withdrawal{Reason: "fixed", At: now}); !errors.Is(err, disposition.ErrNoActor) {
		t.Errorf("a withdrawal without an actor was answered %v, %v", withdrawn, err)
	}
}

func TestADispositionIsInForceUntilItExpiresOrIsWithdrawn(t *testing.T) {
	made := recorded(t)
	expiry := made.GetExpiresAt().AsTime()

	for name, held := range map[string]struct {
		at    time.Time
		force bool
	}{
		"the moment it is recorded":       {now, true},
		"a microsecond before its expiry": {expiry.Add(-time.Microsecond), true},
		"the moment it expires":           {expiry, false},
		"after it expired":                {expiry.Add(day), false},
	} {
		if got := disposition.InForce(made, held.at); got != held.force {
			t.Errorf("%s: in force %v, want %v", name, got, held.force)
		}
	}

	withdrawn, err := disposition.Withdraw(made, disposition.Withdrawal{Reason: "fixed", Actor: "dev-admin", At: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if disposition.InForce(withdrawn, now.Add(2*time.Hour)) {
		t.Error("a withdrawn disposition is in force")
	}
}

func TestADispositionIsNamedOnlyTheWayThePlatformDrawsIt(t *testing.T) {
	for _, written := range []string{
		"",
		"0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f",
		"0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f60",
		"0F8E4A52-1C3B-4D6E-9F70-A1B2C3D4E5F6",
		"0f8e4a521c3b4d6e9f70a1b2c3d4e5f6ab12",
		"0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5g6",
		"../../../etc/passwd/0f8e4a52-1c3b-4d",
	} {
		if disposition.ValidID(written) {
			t.Errorf("%q is accepted as the name of a disposition", written)
		}
	}
	if !disposition.ValidID("0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6") {
		t.Error("a name written the way the platform draws one is refused")
	}
}

// A stored row names its kind in words, and rows an earlier build wrote are read
// by every later one, so each kind keeps the name it was first written under.
func TestEveryKindTheContractDeclaresIsKeptUnderItsOwnName(t *testing.T) {
	names := map[vulnerabilityv1.DispositionKind]disposition.Kind{
		vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED:       "ignored",
		vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK: "accepted_risk",
	}
	for wire := range vulnerabilityv1.DispositionKind_name {
		declared := vulnerabilityv1.DispositionKind(wire)
		kind, known := disposition.KindOf(declared)
		if declared == vulnerabilityv1.DispositionKind_DISPOSITION_KIND_UNSPECIFIED {
			if known {
				t.Errorf("the unspecified kind is kept as %q", kind)
			}
			continue
		}
		if want, named := names[declared]; !named || !known || kind != want {
			t.Errorf("%s is kept as %q (%v), want %q", declared, kind, known, names[declared])
			continue
		}
		if back := kind.Wire(); back != declared {
			t.Errorf("%s is kept as %q and read back as %s", declared, kind, back)
		}
	}
	if kind, known := disposition.KindOf(9); known {
		t.Errorf("an undeclared kind is kept as %q", kind)
	}
	if read := disposition.Kind("waived").Wire(); read != vulnerabilityv1.DispositionKind_DISPOSITION_KIND_UNSPECIFIED {
		t.Errorf("a stored kind this build does not know reads as %s", read)
	}
}
