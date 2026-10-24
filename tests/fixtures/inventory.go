package fixtures

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
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
	Source       string
	Vendor       string
	SizeBytes    uint64
	InstalledAt  time.Time
}

// What dpkg reports of a package on Debian 12, about 180 bytes an item once
// encoded, so a scan of them weighs what an estate's package lists do.
func DebianPackages(count int) []Installed {
	installed := make([]Installed, count)
	for index := range installed {
		installed[index] = Installed{
			Name:         fmt.Sprintf("libgnome-desktop-%05d", index),
			Version:      "1:2.36.1-8+deb12u1",
			Architecture: "amd64",
			Manager:      "dpkg",
			Source:       fmt.Sprintf("gnome-desktop-%05d (2.36.1-8+deb12u1)", index),
			Vendor:       "Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>",
			SizeBytes:    2_461_696,
			InstalledAt:  time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC),
		}
	}
	return installed
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
		held := &inventoryv1.Package{
			Name:         installed.Name,
			Version:      installed.Version,
			Architecture: installed.Architecture,
			Manager:      installed.Manager,
			Source:       installed.Source,
			Vendor:       installed.Vendor,
			SizeBytes:    installed.SizeBytes,
		}
		if !installed.InstalledAt.IsZero() {
			held.InstalledAt = timestamppb.New(installed.InstalledAt)
		}
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: held}})
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

// Fills a process snapshot with processes until the record encodes to exactly
// size bytes, which is how a ceiling counted in bytes is reached on the byte.
// Every pid and command line keeps its length prefix at one width, so each
// process weighs the same and the last one is fitted to the byte.
func Weigh(record *inventoryv1.Record, size int) bool {
	running := func(command int) *inventoryv1.Item {
		return &inventoryv1.Item{Body: &inventoryv1.Item_Process{Process: &inventoryv1.Process{
			Pid:         uint32(1<<14 + len(record.Items)),
			Name:        "java",
			CommandLine: strings.Repeat("x", command),
		}}}
	}

	const filled, room = 4_000, 300
	base := proto.Size(record)
	if size-base < room {
		return false
	}
	record.Items = append(record.Items, running(filled))
	each := proto.Size(record) - base
	record.Items = record.Items[:len(record.Items)-1]
	for count := (size - room - base) / each; count > 0; count-- {
		record.Items = append(record.Items, running(filled))
	}

	record.Items = append(record.Items, running(128))
	length := 128 + size - proto.Size(record)
	if length < 128 || length > inventory.MaxCommandLineLength {
		return false
	}
	record.Items[len(record.Items)-1].GetProcess().CommandLine = strings.Repeat("x", length)
	return proto.Size(record) == size
}
