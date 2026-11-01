package inventory

import (
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// The managers whose database keeps one version of a name and architecture, so
// that a second replaces the first: dpkg, apt over the same database, and apk.
// Nothing else is declared, because a manager wrongly listed here folds two
// instances into one row, and one wrongly left out only costs a name.
var heldOnce = map[string]bool{"dpkg": true, "apt": true, "apk": true}

// What every item of a record is called, in the order the record names them.
//
// A record is the only thing that can say an identity covers several items: a
// snapshot is the whole of what a manager holds, so two versions of one package
// in it are that manager saying both are installed, whatever it calls a kernel,
// and a version shown alone keeps the identity an upgrade replaces. A delta is
// part of an asset and cannot say a version replaced another, so it names the
// instance it saw and leaves the rest to the next snapshot. One identity is
// therefore not a function of one item, and nothing outside a record derives it.
func ItemIDs(record *inventoryv1.Record) []string {
	kind, items := record.GetKind(), record.GetItems()

	identifiers := make([]string, len(items))
	for index, item := range items {
		identifiers[index] = ItemID(kind, item)
	}

	shape := shapes[kind]
	if shape.instance == nil {
		return identifiers
	}

	partial := record.GetMode() == inventoryv1.Mode_MODE_DELTA
	several := shownSeveral(identifiers, items, shape.instance)
	for index, item := range items {
		told, tellable := shape.instance(item)
		if tellable && (partial || several[identifiers[index]]) {
			identifiers[index] = digestOf(kind, append(shape.identify(item), told))
		}
	}
	return identifiers
}

func shownSeveral(identifiers []string, items []*inventoryv1.Item, instance func(*inventoryv1.Item) (string, bool)) map[string]bool {
	first := map[string]string{}
	several := map[string]bool{}
	for index, item := range items {
		told, tellable := instance(item)
		if !tellable {
			continue
		}
		if shown, seen := first[identifiers[index]]; !seen {
			first[identifiers[index]] = told
		} else if shown != told {
			several[identifiers[index]] = true
		}
	}
	return several
}
