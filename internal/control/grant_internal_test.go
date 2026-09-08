package control

import (
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

// A grant is what a caller is shown of what they hold, and a resource in neither
// the map nor the list would be authorised server-side and never appear there.
// Reading both together is what keeps that a decision rather than an oversight.
func TestEveryResourceIsEitherNamedByTheContractOrDeclaredUnnamed(t *testing.T) {
	for _, resource := range authz.Resources() {
		_, named := resources[resource]
		if named == slices.Contains(unnamed, resource) {
			t.Errorf("%s is neither named by the contract nor declared unnamed, or is both", resource)
		}
	}
	for _, resource := range unnamed {
		if !resource.Valid() {
			t.Errorf("%s is declared unnamed and is not a resource", resource)
		}
	}
}

func TestEveryActionIsNamedByTheContract(t *testing.T) {
	for _, action := range authz.Actions() {
		if _, named := actions[action]; !named {
			t.Errorf("%s is not named by the contract", action)
		}
	}
}
