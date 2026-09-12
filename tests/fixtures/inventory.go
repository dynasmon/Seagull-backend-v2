package fixtures

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

type Installed struct {
	Name         string
	Version      string
	Architecture string
	Manager      string
}

type PackageScan struct {
	RecordID string
	AgentID  string
	Hostname string
	At       time.Time
	Mode     inventoryv1.Mode
	Packages []Installed
}

func (p PackageScan) Record() *inventoryv1.Record {
	if p.RecordID == "" {
		p.RecordID = "inv-0000000001"
	}
	if p.AgentID == "" {
		p.AgentID = "dev-agent-01"
	}
	if p.At.IsZero() {
		p.At = time.Now().UTC()
	}
	if p.Mode == inventoryv1.Mode_MODE_UNSPECIFIED {
		p.Mode = inventoryv1.Mode_MODE_SNAPSHOT
	}
	if p.Packages == nil {
		p.Packages = []Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}}
	}

	items := make([]*inventoryv1.Item, 0, len(p.Packages))
	for _, installed := range p.Packages {
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_Package{
			Package: &inventoryv1.Package{
				Name:         installed.Name,
				Version:      installed.Version,
				Architecture: installed.Architecture,
				Manager:      installed.Manager,
			},
		}})
	}

	return &inventoryv1.Record{
		RecordId:      p.RecordID,
		SchemaVersion: inventory.SchemaVersion,
		Kind:          inventoryv1.Kind_KIND_PACKAGE,
		Mode:          p.Mode,
		CollectedAt:   timestamppb.New(p.At),
		Origin: &eventv1.Origin{
			AgentId:  p.AgentID,
			TenantId: "default",
			Host:     &eventv1.Host{Hostname: p.Hostname, Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "syscollector", Source: "dpkg"},
		Items:      items,
	}
}

func InventoryBatch(batchID string, records ...*inventoryv1.Record) *inventoryv1.RecordBatch {
	return &inventoryv1.RecordBatch{
		BatchId:         batchID,
		ProtocolVersion: protocol.Version,
		Records:         records,
	}
}
