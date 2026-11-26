package auditstore

import (
	"errors"
	"fmt"
	"slices"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

var errUnordered = errors.New("the audit store answered a later read with less than an earlier one")

type admitted struct {
	record   Record
	recorded *auditv1.Event
}

type linked struct {
	rows       []Row
	replayed   int
	duplicates int
	misplaced  []Refused
}

func asked(batch []admitted) map[string][]string {
	identifiers := map[string][]string{}
	for _, one := range batch {
		chain := one.recorded.GetTenantId()
		identifiers[chain] = append(identifiers[chain], one.recorded.GetEventId())
	}
	return identifiers
}

func chainsOf(batch []admitted) []string {
	chains := make([]string, 0, len(batch))
	for _, one := range batch {
		chains = append(chains, one.recorded.GetTenantId())
	}
	slices.Sort(chains)
	return slices.Compact(chains)
}

// What each record of a batch becomes, from where its chain stood in the store:
// an entry after the chain's newest, or nothing when the chain already holds it.
// An entry depends on nothing but the entry before it and the record, and a
// chain's records are one partition read in order, so a writer that recovered,
// one that lost its partition and one that never stopped make the same entries.
//
// The identifiers a chain holds were read before its head. A later read sees
// everything an earlier one saw, so one held beyond the head means the store did
// not read its own writes in order, and nothing is decided on that.
func link(batch []admitted, heads map[string]Head, chained map[string]map[string]uint64) (linked, error) {
	for chain, held := range chained {
		head, started := heads[chain]
		for _, sequence := range held {
			if !started || sequence > head.Sequence {
				return linked{}, errUnordered
			}
		}
	}

	var result linked
	standing := make(map[string]Head, len(heads))
	for chain, head := range heads {
		standing[chain] = head
	}
	appended := map[string]map[string]bool{}
	for _, one := range batch {
		name, id := one.recorded.GetTenantId(), one.recorded.GetEventId()
		head, started := standing[name]
		_, held := chained[name][id]
		switch {
		case started && head.Partition != one.record.Partition:
			result.misplaced = append(result.misplaced, refuse(one.record, ReasonMisplaced,
				fmt.Sprintf("the record's chain is read from partition %d", head.Partition)))
			continue
		case started && one.record.Offset <= head.Offset:
			result.replayed++
			continue
		case held || appended[name][id]:
			result.duplicates++
			continue
		}

		entry, next, err := audit.Chain{Name: name, Sequence: head.Sequence, Head: head.Digest}.Append(one.record.Value)
		if err != nil {
			return linked{}, fmt.Errorf("chain the record at offset %d of partition %d: %w", one.record.Offset, one.record.Partition, err)
		}
		result.rows = append(result.rows, project(entry, one.recorded, one.record))
		standing[name] = Head{Sequence: next.Sequence, Digest: next.Head, Partition: one.record.Partition, Offset: one.record.Offset}
		if appended[name] == nil {
			appended[name] = map[string]bool{}
		}
		appended[name][id] = true
	}
	return result, nil
}

func refuse(record Record, reason, detail string) Refused {
	return Refused{
		Key:       record.Key,
		Value:     record.Value,
		Reason:    reason,
		Detail:    detail,
		Partition: record.Partition,
		Offset:    record.Offset,
	}
}
