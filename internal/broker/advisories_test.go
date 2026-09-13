package broker

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func advisoryRecord(source, id string, modified time.Time) *vulnerabilityv1.Record {
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: &vulnerabilityv1.Advisory{
		Source: source, Id: id, Modified: timestamppb.New(modified),
	}}}
}

func syncRecord(source, feed string) *vulnerabilityv1.Record {
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{Source: source, Feed: feed}}}
}

// Compaction keeps the last record of a key, so the key is what decides what
// survives: every version of an advisory has to share one, and nothing else may.
func TestEveryVersionOfAnAdvisorySharesAKeyAndNothingElseDoes(t *testing.T) {
	now := time.Now()
	keys := map[string]string{}
	for name, record := range map[string]*vulnerabilityv1.Record{
		"the first version":            advisoryRecord("osv", "DSA-6189-1", now.Add(-time.Hour)),
		"another advisory":             advisoryRecord("osv", "DSA-6189-2", now),
		"the same id from elsewhere":   advisoryRecord("nvd", "DSA-6189-1", now),
		"the freshness of a feed":      syncRecord("osv", "Debian"),
		"the freshness of another one": syncRecord("osv", "Ubuntu"),
		"a feed named like an id":      syncRecord("osv", "DSA-6189-1"),
	} {
		key, err := advisoryKey(record)
		if err != nil {
			t.Fatalf("%s has no key: %v", name, err)
		}
		if other, taken := keys[string(key)]; taken {
			t.Errorf("%s and %s share the key %q", name, other, key)
		}
		keys[string(key)] = name
	}

	later, err := advisoryKey(advisoryRecord("osv", "DSA-6189-1", now))
	if err != nil || keys[string(later)] != "the first version" {
		t.Errorf("a newer version of an advisory is keyed %q, apart from the version it replaces", later)
	}

	for _, record := range []*vulnerabilityv1.Record{
		{},
		advisoryRecord("", "DSA-6189-1", now),
		advisoryRecord("osv", "", now),
		syncRecord("osv", ""),
	} {
		if key, err := advisoryKey(record); err == nil {
			t.Errorf("%v was keyed %q", record, key)
		}
	}
}
