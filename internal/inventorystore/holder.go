package inventorystore

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var packageKind = inventory.KindName(inventoryv1.Kind_KIND_PACKAGE)

// An asset holding a package under one name an advisory may call it by. It
// says where to look and not what is there: whether the package is still
// installed is read from its row against the newest scan.
type Holder struct {
	Package  string
	TenantID string
	AgentID  string
	ItemID   string
	LastSeen time.Time
}

// Read off the rows rather than the record, so a holder names exactly what the
// store keeps and a reader placing the stored package lands on one of its names.
func Holders(rows []Row) []Holder {
	var holders []Holder
	for _, row := range rows {
		if row.Kind != packageKind {
			continue
		}
		installed := &inventoryv1.Package{Name: row.PackageName, Source: row.PackageSource, Manager: row.PackageManager}
		for _, name := range vulnerability.PackageNames(installed) {
			holders = append(holders, Holder{
				Package:  name,
				TenantID: row.TenantID,
				AgentID:  row.AgentID,
				ItemID:   row.ItemID,
				LastSeen: row.LastSeen,
			})
		}
	}
	return holders
}
