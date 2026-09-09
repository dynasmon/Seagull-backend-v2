package control

import (
	"fmt"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

// What a caller may narrow a listing by, decided here rather than by the store.
// A store builds its predicate from the values it recognises, so a filter it
// recognises nothing in becomes no filter at all and the answer widens to
// everything the caller may read — the opposite of what asking for one state
// means. A value the contract does not declare is refused where the caller can
// still see what they asked for.
func alertFilters(asked *alertv1.Query) error {
	for _, state := range asked.GetStates() {
		if _, known := alert.FromWire(state); !known {
			return fmt.Errorf("states names %s, which is not a state an alert is in", state)
		}
	}
	return severities(asked.GetSeverities())
}

func incidentFilters(asked *incidentv1.Query) error {
	for _, state := range asked.GetStates() {
		if _, known := incident.FromWire(state); !known {
			return fmt.Errorf("states names %s, which is not a state an incident is in", state)
		}
	}
	for _, level := range asked.GetConfidences() {
		if incident.Level(level) == "" || !declares(int32(level), incidentv1.Confidence_name) {
			return fmt.Errorf("confidences names %s, which is not a confidence", level)
		}
	}
	return severities(asked.GetSeverities())
}

func agentFilters(asked *agentv1.Query) error {
	for _, state := range asked.GetStates() {
		if _, known := agent.FromWire(state); !known {
			return fmt.Errorf("states names %s, which is not a state an agent is in", state)
		}
	}
	return nil
}

func severities(asked []detectionv1.Severity) error {
	for _, severity := range asked {
		if severity == detectionv1.Severity_SEVERITY_UNSPECIFIED || !declares(int32(severity), detectionv1.Severity_name) {
			return fmt.Errorf("severities names %s, which is not a severity", severity)
		}
	}
	return nil
}

func declares(value int32, names map[int32]string) bool {
	_, named := names[value]
	return named
}
