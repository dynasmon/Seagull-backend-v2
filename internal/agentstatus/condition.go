package agentstatus

import (
	"strings"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// The word a condition is stored and counted under, such as `degraded`.
func ConditionName(condition agentv1.Status_Condition) string {
	return strings.ToLower(strings.TrimPrefix(condition.String(), "CONDITION_"))
}
