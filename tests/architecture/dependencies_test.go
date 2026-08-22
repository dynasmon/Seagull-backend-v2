package architecture_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/dynasmon/Seagull-backend-v2"

type layer string

const (
	platform    layer = "platform"
	domain      layer = "domain"
	capability  layer = "capability"
	adapter     layer = "adapter"
	development layer = "development"
	tool        layer = "tool"
	executable  layer = "executable"
	suite       layer = "suite"
)

// Every package this module owns is named here, and TestEveryPackageIsClassified
// refuses one that is not, so a capability added tomorrow is governed by the
// rules below instead of by nothing. The longest matching prefix wins.
var layers = map[string]layer{
	"cmd":                    executable,
	"internal/agentidentity": domain,
	"internal/analysis":      capability,
	"internal/broker":        adapter,
	"internal/clickhouse":    adapter,
	"internal/devpki":        development,
	"internal/event":         domain,
	"internal/eventstore":    capability,
	"internal/ingest":        capability,
	"internal/platform":      platform,
	"internal/protocol":      domain,
	"tests":                  suite,
	"tools":                  tool,
}

// What each layer may name among the packages this module owns, on top of its
// own subtree. Absence is a refusal: a capability may not name another
// capability, an adapter may not name another adapter, nothing may name an
// executable, and no process that ships may name development material.
var mayImport = map[layer][]layer{
	platform:    {platform},
	domain:      {domain},
	capability:  {domain, platform},
	adapter:     {domain, platform, capability},
	development: {development},
	tool:        {domain, platform, capability, adapter, development},
	executable:  {domain, platform, capability, adapter},
	suite:       {domain, platform, capability, adapter, development},
}

var named = map[layer]string{
	platform:    "only a capability, an adapter or an executable may name the platform",
	domain:      "the domain is named by capabilities, adapters and executables, never by the platform",
	capability:  "a capability is named by an adapter or an executable; two capabilities reach each other over the backbone",
	adapter:     "an adapter is named by an executable, which is where an implementation is chosen",
	development: "development material is named by tools and tests, never by a process that ships",
	tool:        "a tool is a program, not a library",
	executable:  "an executable is an entry point, not a library",
	suite:       "a suite verifies the tree and is not part of it",
}

type restriction struct {
	prefixes []string
	because  string
}

// Infrastructure a layer may not name outside this module. The platform is
// infrastructure and an adapter exists to hold a client, so neither is listed.
var outside = map[layer]restriction{
	domain: {
		prefixes: []string{
			"net/http",
			"database/sql",
			"github.com/ClickHouse",
			"github.com/prometheus/client_golang",
			"github.com/twmb/franz-go",
		},
		because: "a domain states what something is and needs nothing that runs to state it",
	},
	capability: {
		prefixes: []string{"database/sql", "github.com/ClickHouse", "github.com/twmb/franz-go"},
		because:  "a capability describes what it needs; the adapter holding a client is chosen by an executable",
	},
	executable: {
		prefixes: []string{"database/sql", "github.com/ClickHouse", "github.com/twmb/franz-go"},
		because:  "an executable chooses an adapter; it does not open a connection itself",
	},
}

// A rule that belongs to one package rather than to its layer, because ingest
// is a transport and a rule about capabilities would refuse it too.
var within = map[string]restriction{
	"internal/analysis": {
		prefixes: []string{
			"net/http",
			modulePath + "/internal/platform/httpx",
			modulePath + "/internal/platform/tlsx",
		},
		because: "what analysing an event means has no transport of its own: this half is reached from the backbone",
	},
	"internal/eventstore": {
		prefixes: []string{
			"net/http",
			modulePath + "/internal/platform/httpx",
			modulePath + "/internal/platform/tlsx",
		},
		because: "what a stored event is has no transport of its own: this half is reached from the backbone",
	},
}

type pkg struct {
	path    string
	imports []string
}

func packages(t *testing.T) []pkg {
	t.Helper()

	command := exec.Command("go", "list", "-tags", "integration", "-f", "{{.ImportPath}}|{{join .Imports \",\"}}", "./...")
	command.Dir = moduleRoot(t)

	var refusal bytes.Buffer
	command.Stderr = &refusal
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list packages: %v\n%s", err, strings.TrimSpace(refusal.String()))
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

func owned(importPath string) (string, bool) {
	if !strings.HasPrefix(importPath, modulePath+"/") {
		return "", false
	}
	return strings.TrimPrefix(importPath, modulePath+"/"), true
}

func classify(name string) (string, layer, bool) {
	longest := ""
	for prefix := range layers {
		if name != prefix && !strings.HasPrefix(name, prefix+"/") {
			continue
		}
		if len(prefix) > len(longest) {
			longest = prefix
		}
	}
	if longest == "" {
		return "", "", false
	}
	return longest, layers[longest], true
}

func permits(from, to layer) bool {
	for _, allowed := range mayImport[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

func TestEveryPackageIsClassified(t *testing.T) {
	for _, entry := range packages(t) {
		name, ours := owned(entry.path)
		if !ours {
			t.Errorf("%s is listed by this module but is not part of it", entry.path)
			continue
		}
		if _, _, known := classify(name); !known {
			t.Errorf("%s has no layer: name it in tests/architecture so the dependency rules reach it", name)
		}
	}
}

func TestDependenciesFollowTheLayers(t *testing.T) {
	for _, entry := range packages(t) {
		name, ours := owned(entry.path)
		if !ours {
			continue
		}
		root, from, known := classify(name)
		if !known {
			continue
		}
		for _, imported := range entry.imports {
			target, ours := owned(imported)
			if !ours {
				continue
			}
			branch, to, known := classify(target)
			if !known || branch == root || permits(from, to) {
				continue
			}
			t.Errorf("%s (%s) imports %s (%s): %s", name, from, target, to, named[to])
		}
	}
}

func TestNoPackageNamesInfrastructureItMustNotKnow(t *testing.T) {
	for _, entry := range packages(t) {
		name, ours := owned(entry.path)
		if !ours {
			continue
		}
		_, from, known := classify(name)
		if !known {
			continue
		}
		refused := []restriction{outside[from]}
		if own, declared := within[name]; declared {
			refused = append(refused, own)
		}
		for _, imported := range entry.imports {
			for _, rule := range refused {
				for _, prefix := range rule.prefixes {
					if imported == prefix || strings.HasPrefix(imported, prefix+"/") {
						t.Errorf("%s (%s) imports %s: %s", name, from, imported, rule.because)
					}
				}
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
