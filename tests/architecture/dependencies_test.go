package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/dynasmon/Seagull-backend-v2"

type pkg struct {
	path    string
	imports []string
}

func packages(t *testing.T) []pkg {
	t.Helper()

	command := exec.Command("go", "list", "-f", "{{.ImportPath}}|{{join .Imports \",\"}}", "./...")
	command.Dir = moduleRoot(t)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list packages: %v", err)
	}

	var listed []pkg
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		path, imports, _ := strings.Cut(line, "|")
		entry := pkg{path: path}
		for _, name := range strings.Split(imports, ",") {
			if name != "" {
				entry.imports = append(entry.imports, name)
			}
		}
		listed = append(listed, entry)
	}
	if len(listed) == 0 {
		t.Fatal("no packages were listed")
	}
	return listed
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	return root
}

func local(importPath string) bool { return strings.HasPrefix(importPath, modulePath+"/") }

func within(importPath, prefix string) bool {
	full := modulePath + "/" + prefix
	return importPath == full || strings.HasPrefix(importPath, full+"/")
}

func TestPlatformDoesNotKnowTheProduct(t *testing.T) {
	for _, entry := range packages(t) {
		if !within(entry.path, "internal/platform") {
			continue
		}
		for _, imported := range entry.imports {
			if !local(imported) || within(imported, "internal/platform") {
				continue
			}
			t.Errorf("%s imports %s: the platform must stay free of product packages", entry.path, imported)
		}
	}
}

func TestDomainDoesNotKnowInfrastructure(t *testing.T) {
	domains := []string{"internal/event", "internal/agentidentity", "internal/protocol"}
	forbidden := []string{
		"net/http",
		"database/sql",
		"github.com/twmb/franz-go",
		"github.com/prometheus/client_golang",
		modulePath + "/internal/platform/httpx",
		modulePath + "/internal/platform/metrics",
		modulePath + "/internal/platform/ops",
		modulePath + "/internal/platform/service",
		modulePath + "/internal/platform/tlsx",
		modulePath + "/internal/broker",
		modulePath + "/internal/ingest",
	}

	for _, entry := range packages(t) {
		inDomain := false
		for _, domain := range domains {
			if within(entry.path, domain) {
				inDomain = true
				break
			}
		}
		if !inDomain {
			continue
		}
		for _, imported := range entry.imports {
			for _, banned := range forbidden {
				if imported == banned || strings.HasPrefix(imported, banned+"/") {
					t.Errorf("%s imports %s: the domain must not depend on infrastructure", entry.path, imported)
				}
			}
		}
	}
}

// The gateway depends on an interface it owns, not on the broker client. Only
// the executable is allowed to name the concrete backbone.
func TestOnlyExecutablesWireTheBroker(t *testing.T) {
	for _, entry := range packages(t) {
		if within(entry.path, "cmd") || within(entry.path, "internal/broker") {
			continue
		}
		for _, imported := range entry.imports {
			if within(imported, "internal/broker") {
				t.Errorf("%s imports %s: only an executable may choose the backbone implementation", entry.path, imported)
			}
		}
	}
}

// The same rule for the store. An adapter may name the capability it plugs into;
// the reverse would make the capability describe a particular database.
func TestOnlyExecutablesWireTheStore(t *testing.T) {
	for _, entry := range packages(t) {
		if within(entry.path, "cmd") || within(entry.path, "internal/clickhouse") {
			continue
		}
		for _, imported := range entry.imports {
			if within(imported, "internal/clickhouse") {
				t.Errorf("%s imports %s: only an executable may choose the store implementation", entry.path, imported)
			}
		}
	}
}

// The writing capability owns what a stored row is and what is refused. It must
// be able to state that without a transport, a driver or a broker client.
func TestTheStoringCapabilityDoesNotKnowItsAdapters(t *testing.T) {
	forbidden := []string{
		"net/http",
		"database/sql",
		"github.com/twmb/franz-go",
		"github.com/ClickHouse",
		modulePath + "/internal/broker",
		modulePath + "/internal/clickhouse",
		modulePath + "/internal/ingest",
		modulePath + "/internal/platform/httpx",
		modulePath + "/internal/platform/tlsx",
	}

	for _, entry := range packages(t) {
		if !within(entry.path, "internal/eventstore") {
			continue
		}
		for _, imported := range entry.imports {
			for _, banned := range forbidden {
				if imported == banned || strings.HasPrefix(imported, banned+"/") {
					t.Errorf("%s imports %s: the writing capability must not name an adapter", entry.path, imported)
				}
			}
		}
	}
}

// The two halves of the data plane meet on the backbone, never in Go.
func TestTheTwoHalvesOfTheDataPlaneDoNotKnowEachOther(t *testing.T) {
	for _, entry := range packages(t) {
		var opposite string
		switch {
		case within(entry.path, "internal/ingest"):
			opposite = "internal/eventstore"
		case within(entry.path, "internal/eventstore"):
			opposite = "internal/ingest"
		default:
			continue
		}
		for _, imported := range entry.imports {
			if within(imported, opposite) {
				t.Errorf("%s imports %s: the two halves of the data plane meet on the backbone, not in Go", entry.path, imported)
			}
		}
	}
}

func TestNothingImportsAnExecutable(t *testing.T) {
	for _, entry := range packages(t) {
		for _, imported := range entry.imports {
			if within(imported, "cmd") {
				t.Errorf("%s imports %s: executables are entry points, not libraries", entry.path, imported)
			}
		}
	}
}

func TestNoPackageWithoutOwnership(t *testing.T) {
	unowned := map[string]struct{}{
		"utils": {}, "util": {}, "helpers": {}, "helper": {},
		"common": {}, "misc": {}, "shared": {}, "base": {}, "core": {},
	}

	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name == ".git" || name == ".local" || name == "node_modules" {
			return filepath.SkipDir
		}
		if _, banned := unowned[name]; banned {
			relative, _ := filepath.Rel(root, path)
			t.Errorf("%s is a package without an owner: name it after what it is responsible for", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
}
