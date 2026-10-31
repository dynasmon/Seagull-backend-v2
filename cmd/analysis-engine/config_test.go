package main

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func environment(t *testing.T, set map[string]string) *config.Parser {
	t.Helper()

	values := map[string]string{
		"SEAGULL_BACKBONE_BROKERS":        "127.0.0.1:9092",
		"SEAGULL_BACKBONE_SASL_MECHANISM": "none",
		"SEAGULL_DETECTION_RULES":         t.TempDir(),
	}
	for key, value := range set {
		values[key] = value
	}
	return config.New(func(key string) (string, bool) {
		value, given := values[key]
		return value, given
	})
}

func TestAStoreDeclaredAloneIsCarvedSoThatNoTenantCanFillIt(t *testing.T) {
	for _, one := range []struct {
		keys, perTenant, perRule string
		wantTenant, wantRule     int
	}{
		{wantTenant: 1024, wantRule: 512},
		{keys: "1048576", wantTenant: 262144, wantRule: 131072},
		{keys: "1", wantTenant: 1, wantRule: 1},
		{keys: "3", wantTenant: 1, wantRule: 1},
		{keys: "4096", perTenant: "4096", wantTenant: 4096, wantRule: 2048},
		{keys: "4096", perTenant: "4096", perRule: "4096", wantTenant: 4096, wantRule: 4096},
		{keys: "4096", perRule: "16", wantTenant: 1024, wantRule: 16},
	} {
		set := map[string]string{}
		if one.keys != "" {
			set["SEAGULL_DETECTION_STATE_KEYS"] = one.keys
		}
		if one.perTenant != "" {
			set["SEAGULL_DETECTION_STATE_KEYS_PER_TENANT"] = one.perTenant
		}
		if one.perRule != "" {
			set["SEAGULL_DETECTION_STATE_KEYS_PER_RULE"] = one.perRule
		}

		loaded, err := load(environment(t, set))
		if err != nil {
			t.Fatalf("%+v was refused: %v", one, err)
		}
		if loaded.state.KeysPerTenant != one.wantTenant || loaded.state.KeysPerRule != one.wantRule {
			t.Errorf("%+v gave a tenant %d keys and a rule %d", one, loaded.state.KeysPerTenant, loaded.state.KeysPerRule)
		}
		if _, err := keeping(runtime{
			bounds:       loaded.state,
			partitioning: detectionstate.Partitioning{By: broker.PartitionedBy},
		}, nil); err != nil {
			t.Errorf("%+v loaded and the store refused to open: %v", one, err)
		}
	}
}

func TestAQuotaWiderThanWhatItIsCarvedFromStopsTheProcess(t *testing.T) {
	for setting, set := range map[string]map[string]string{
		"SEAGULL_DETECTION_STATE_KEYS_PER_TENANT": {
			"SEAGULL_DETECTION_STATE_KEYS":            "8",
			"SEAGULL_DETECTION_STATE_KEYS_PER_TENANT": "9",
		},
		"SEAGULL_DETECTION_STATE_KEYS_PER_RULE": {
			"SEAGULL_DETECTION_STATE_KEYS":            "8",
			"SEAGULL_DETECTION_STATE_KEYS_PER_TENANT": "4",
			"SEAGULL_DETECTION_STATE_KEYS_PER_RULE":   "5",
		},
	} {
		if _, err := load(environment(t, set)); err == nil || !strings.Contains(err.Error(), setting) {
			t.Errorf("%v was answered %v, which does not name %s", set, err, setting)
		}
	}
}
