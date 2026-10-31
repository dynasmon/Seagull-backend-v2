package analysis_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func shared(keys, perTenant, perRule int) detectionstate.Bounds {
	return detectionstate.Bounds{
		Window:             time.Hour,
		ObservationsPerKey: 8,
		Keys:               keys,
		KeysPerTenant:      perTenant,
		KeysPerRule:        perRule,
	}
}

func failureOf(t *testing.T, owner string, at time.Time, source string) analysis.Record {
	t.Helper()

	record := fixtures.SSHAuthentication{
		EventID:  fmt.Sprintf("%s-%s-%d", owner, source, at.UnixNano()),
		SourceIP: source,
		At:       at,
	}.Event()
	record.Origin.TenantId = owner

	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return analysis.Record{Offset: at.Unix(), Value: payload}
}

func onPartition(partition int32, record analysis.Record) analysis.Record {
	record.Partition = partition
	return record
}

func TestATenantFloodingGroupValuesDoesNotBlindAnotherTenantsRule(t *testing.T) {
	program := threshold(t, 3, time.Minute, "authentication.network.source.ip", "origin.agent_id")

	var stream []analysis.Record
	for index := range 64 {
		stream = append(stream, failureOf(t, "flooding", began, fmt.Sprintf("198.51.100.%d", index)))
	}
	for index := range 3 {
		stream = append(stream, failureOf(t, "another", began.Add(time.Duration(index)*time.Second), "203.0.113.10"))
	}

	made, _ := held(t, shared(8, 4, 4), program, stream)
	if len(made) != 1 {
		t.Fatalf("three failures of a tenant beside another's flood made %d detections", len(made))
	}
	if owner := made[0].GetOrigin().GetTenantId(); owner != "another" {
		t.Errorf("the detection belongs to %q", owner)
	}
}

func TestARefusalIsCountedAsTheQuotaThatOverflowed(t *testing.T) {
	program := threshold(t, 2, time.Minute, "authentication.network.source.ip")

	for _, one := range []struct {
		name    string
		bounds  detectionstate.Bounds
		owners  []string
		outcome string
	}{
		{"the store", shared(2, 2, 1), []string{"one", "two", "three"}, "at_capacity"},
		{"the tenant", shared(8, 2, 2), []string{"one", "one", "one"}, "tenant_at_capacity"},
		{"a rule", shared(8, 4, 2), []string{"one", "one", "one"}, "rule_at_capacity"},
	} {
		t.Run(one.name, func(t *testing.T) {
			var stream []analysis.Record
			for index, owner := range one.owners {
				stream = append(stream, failureOf(t, owner, began, fmt.Sprintf("198.51.100.%d", index)))
			}

			_, registry := held(t, one.bounds, program, stream)

			expected := fmt.Sprintf(`seagull_detection_state_observations_total{outcome=%q} 1`, one.outcome)
			if body := exposition(t, registry); !strings.Contains(body, expected) {
				t.Errorf("%q is missing from the exposition: %s", expected, body)
			}
		})
	}
}

// A partition read back while another runs ahead, under pressure: what the rule
// was in the middle of counting on it is still there when the rest of its window
// arrives, which only a watermark of its own can see.
func TestAWindowBehindTheStreamReachesItsThresholdUnderPressure(t *testing.T) {
	program := threshold(t, 3, time.Minute, "authentication.network.source.ip", "origin.agent_id")

	made, _ := held(t, shared(2, 2, 2), program, []analysis.Record{
		onPartition(1, failure(t, began, "203.0.113.10")),
		onPartition(0, failure(t, began.Add(time.Hour), "198.51.100.1")),
		onPartition(1, failure(t, began.Add(time.Second), "198.51.100.2")),
		onPartition(1, failure(t, began.Add(2*time.Second), "203.0.113.10")),
		onPartition(1, failure(t, began.Add(3*time.Second), "203.0.113.10")),
	})

	if len(made) != 1 {
		t.Fatalf("three failures inside a minute on a partition behind the stream made %d detections", len(made))
	}
}

func TestAStoryBehindTheStreamIsToldUnderPressure(t *testing.T) {
	program := story(t, time.Minute, "authentication.network.source.ip", "origin.agent_id")

	made, _ := held(t, shared(2, 2, 2), program, []analysis.Record{
		onPartition(1, staged(t, timed{at: began, outcome: eventv1.Outcome_OUTCOME_FAILURE, source: "203.0.113.10"})),
		onPartition(0, staged(t, timed{at: began.Add(time.Hour), outcome: eventv1.Outcome_OUTCOME_FAILURE, source: "198.51.100.1"})),
		onPartition(1, staged(t, timed{at: began.Add(time.Second), outcome: eventv1.Outcome_OUTCOME_FAILURE, source: "198.51.100.2"})),
		onPartition(1, staged(t, timed{at: began.Add(2 * time.Second), outcome: eventv1.Outcome_OUTCOME_SUCCESS, source: "203.0.113.10"})),
	})

	if len(made) != 1 {
		t.Fatalf("a story on a partition behind the stream made %d detections", len(made))
	}
}

func TestAQuotaNamesWhoReachedItOnceRatherThanOncePerEvent(t *testing.T) {
	program := threshold(t, 2, time.Minute, "authentication.network.source.ip")

	var flood []analysis.Record
	for index := range 32 {
		flood = append(flood, failureOf(t, "flooding", began, fmt.Sprintf("198.51.100.%d", index)))
	}

	_, registry, told := heldAndTold(t, shared(8, 2, 2), program, flood)

	if lines := strings.Count(told, `"msg":"detection_state_at_capacity"`); lines != 1 {
		t.Fatalf("thirty refused events were told in %d lines: %s", lines, told)
	}
	for _, named := range []string{
		`"tenant":"flooding"`,
		`"rule":"ssh.repeated_failed_password"`,
		`"outcome":"tenant_at_capacity"`,
	} {
		if !strings.Contains(told, named) {
			t.Errorf("%s is missing from %s", named, told)
		}
	}
	expected := `seagull_detection_state_observations_total{outcome="tenant_at_capacity"} 30`
	if body := exposition(t, registry); !strings.Contains(body, expected) {
		t.Errorf("%q is missing from the exposition: %s", expected, body)
	}
}

func TestWhatAQuotaRemembersHavingToldIsBounded(t *testing.T) {
	program := threshold(t, 2, time.Minute, "authentication.network.source.ip")

	flood := make([]analysis.Record, 0, 1_100)
	for index := range 1_100 {
		flood = append(flood, failureOf(t, fmt.Sprintf("tenant-%d", index), began, "198.51.100.1"))
	}

	_, registry, told := heldAndTold(t, shared(1, 1, 1), program, flood)

	if lines := strings.Count(told, `"msg":"detection_state_at_capacity"`); lines != 1_024 {
		t.Errorf("1,099 tenants refused were told in %d lines, want the 1,024 the set is bounded to", lines)
	}
	expected := `seagull_detection_state_observations_total{outcome="at_capacity"} 1099`
	if body := exposition(t, registry); !strings.Contains(body, expected) {
		t.Errorf("past the bound the counter went on saying less than %q: %s", expected, body)
	}
}

func TestTheFullestTenantAndRuleAreReportedBesideTheirCeilings(t *testing.T) {
	bounds := shared(8, 4, 2)
	keeper, err := detectionstate.NewKeeper(bounds)
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}
	registry := metrics.New(t.Name())
	analysis.ObserveState(registry, bounds, keeper)

	for index, group := range []string{"203.0.113.10", "203.0.113.11"} {
		key := detectionstate.KeyFor("one", "a.rule", 1, []detection.Binding{{Field: "authentication.network.source.ip", Value: group}})
		seen := detectionstate.Observation{
			Event: detectionstate.EventName{Agent: "web-01", ID: group},
			At:    began.Add(time.Duration(index) * time.Second),
		}
		if _, err := keeper.Observe(context.Background(), key, seen, time.Minute); err != nil {
			t.Fatalf("observe %s: %v", group, err)
		}
	}

	body := exposition(t, registry)
	for _, expected := range []string{
		"seagull_detection_state_keys 2",
		"seagull_detection_state_tenant_key_ceiling 4",
		"seagull_detection_state_rule_key_ceiling 2",
		"seagull_detection_state_fullest_tenant_keys 2",
		"seagull_detection_state_fullest_rule_keys 2",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("%q is missing from the exposition: %s", expected, body)
		}
	}
}
