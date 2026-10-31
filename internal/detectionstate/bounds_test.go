package detectionstate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

func bounded() detectionstate.Bounds {
	return detectionstate.Bounds{Window: time.Minute, ObservationsPerKey: 8, Keys: 4, KeysPerTenant: 4, KeysPerRule: 4}
}

func quotas(keys, perTenant, perRule int) detectionstate.Bounds {
	return detectionstate.Bounds{
		Window:             window,
		ObservationsPerKey: 8,
		Keys:               keys,
		KeysPerTenant:      perTenant,
		KeysPerRule:        perRule,
	}
}

func TestEveryBoundIsFiniteAndDeclared(t *testing.T) {
	for _, one := range []struct {
		name     string
		bounds   detectionstate.Bounds
		expected error
	}{
		{"whole", bounded(), nil},
		{"unwindowed", detectionstate.Bounds{ObservationsPerKey: 8, Keys: 4, KeysPerTenant: 4, KeysPerRule: 4}, detectionstate.ErrNoWindow},
		{
			"remembering forever",
			detectionstate.Bounds{Window: detectionstate.MaxWindow + time.Second, ObservationsPerKey: 8, Keys: 4, KeysPerTenant: 4, KeysPerRule: 4},
			detectionstate.ErrNoWindow,
		},
		{"holding nothing", detectionstate.Bounds{Window: time.Minute, Keys: 4, KeysPerTenant: 4, KeysPerRule: 4}, detectionstate.ErrNoObservations},
		{
			"holding everything",
			detectionstate.Bounds{Window: time.Minute, ObservationsPerKey: detectionstate.MaxObservationsPerKey + 1, Keys: 4, KeysPerTenant: 4, KeysPerRule: 4},
			detectionstate.ErrNoObservations,
		},
		{"keyless", detectionstate.Bounds{Window: time.Minute, ObservationsPerKey: 8, KeysPerTenant: 4, KeysPerRule: 4}, detectionstate.ErrNoKeys},
		{
			"unbounded keys",
			detectionstate.Bounds{Window: time.Minute, ObservationsPerKey: 8, Keys: detectionstate.MaxKeys + 1, KeysPerTenant: 4, KeysPerRule: 4},
			detectionstate.ErrNoKeys,
		},
		{"a tenant quota of nothing", quotas(4, 0, 4), detectionstate.ErrNoTenantKeys},
		{"a tenant quota wider than the store", quotas(4, 5, 4), detectionstate.ErrNoTenantKeys},
		{"a tenant given the whole store", quotas(4, 4, 4), nil},
		{"a rule quota of nothing", quotas(4, 2, 0), detectionstate.ErrNoRuleKeys},
		{"a rule quota wider than its tenant's", quotas(4, 2, 3), detectionstate.ErrNoRuleKeys},
		{"a rule given its tenant's whole quota", quotas(4, 2, 2), nil},
	} {
		t.Run(one.name, func(t *testing.T) {
			if err := one.bounds.Validate(); !errors.Is(err, one.expected) {
				t.Errorf("validating %s bounds gave %v, wanted %v", one.name, err, one.expected)
			}
		})
	}
}

func TestTheMemoryAStoreCanOccupyIsKnownBeforeItRuns(t *testing.T) {
	if held := bounded().Observations(); held != 32 {
		t.Errorf("four keys of eight observations came to %d, not 32", held)
	}
}
