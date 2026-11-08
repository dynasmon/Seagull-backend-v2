package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The card's invariant, held where the matcher is composed: it constructs a
// reader of the analytical store and the three backbone clients it needs, and
// nothing that writes a store or produces to a stream other than the findings.
func TestTheMatcherConstructsNoWriterButTheFindingsPublisher(t *testing.T) {
	allowed := map[string][]string{
		"clickhouse": {"NewMatchingReader"},
		"broker":     {"NewConsumer", "NewConsumerMetrics", "NewPositions", "NewFindings"},
	}
	directory := filepath.Join(moduleRoot(t), "cmd", "vulnerability-matcher")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	constructed := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(selector.Sel.Name, "New") {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			permitted, governed := allowed[owner.Name]
			if !governed {
				return true
			}
			constructed++
			if !slices.Contains(permitted, selector.Sel.Name) {
				t.Errorf("%s constructs %s.%s, and the matcher writes no store and produces to no stream but the findings", entry.Name(), owner.Name, selector.Sel.Name)
			}
			return true
		})
	}
	if constructed == 0 {
		t.Fatal("the matcher constructs nothing from the store or the backbone, so nothing was checked")
	}
}

func TestTheMatcherReachesNoNetworkButTheInternalBackbone(t *testing.T) {
	var compose struct {
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
		Services map[string]struct {
			Networks []string `yaml:"networks"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatal(err)
	}
	matcher, declared := compose.Services["vulnerability-matcher"]
	if !declared {
		t.Fatal("the development stack runs no vulnerability-matcher")
	}
	if len(matcher.Networks) == 0 {
		t.Fatal("the vulnerability-matcher names no network, and a service naming none joins the default one, which reaches the internet")
	}
	for _, network := range matcher.Networks {
		if !compose.Networks[network].Internal {
			t.Errorf("the vulnerability-matcher joins %s, which is not internal: the matcher holds no internet access", network)
		}
	}
}
