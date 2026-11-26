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
)

const auditWriter = "audit-writer"

// The card's separation, held where processes are composed: the one executable
// that writes the audit trail constructs its store, and no executable it audits
// can, so a component never holds what alters the record of what it did.
func TestOnlyTheAuditWriterConstructsWhatWritesTheAuditTrail(t *testing.T) {
	constructions := constructedBy(t)
	for executable, constructed := range constructions {
		if executable != auditWriter && slices.Contains(constructed, "clickhouse.NewAuditStore") {
			t.Errorf("cmd/%s constructs clickhouse.NewAuditStore, and only the audit writer writes the audit trail", executable)
		}
	}
	if !slices.Contains(constructions[auditWriter], "clickhouse.NewAuditStore") {
		t.Fatal("cmd/audit-writer constructs no audit store, so nothing was checked")
	}

	for _, listed := range packages(t) {
		name, executable := strings.CutPrefix(listed.path, modulePath+"/cmd/")
		if executable && name != auditWriter && slices.Contains(listed.imports, modulePath+"/internal/auditstore") {
			t.Errorf("cmd/%s imports internal/auditstore, which chains the trail it would be audited by", name)
		}
	}
}

func TestTheAuditWriterConstructsNothingButItsStoreAndItsStream(t *testing.T) {
	allowed := []string{
		"clickhouse.NewAuditStore",
		"broker.NewConsumer",
		"broker.NewConsumerMetrics",
		"broker.NewQuarantine",
		"broker.NewDenials",
	}
	constructed := constructedBy(t)[auditWriter]
	for _, one := range constructed {
		if (strings.HasPrefix(one, "clickhouse.") || strings.HasPrefix(one, "broker.") || strings.HasPrefix(one, "postgres.")) &&
			!slices.Contains(allowed, one) {
			t.Errorf("cmd/audit-writer constructs %s, and it writes no store but the trail and produces to no stream but its quarantine", one)
		}
	}
}

func constructedBy(t *testing.T) map[string][]string {
	t.Helper()
	root := filepath.Join(moduleRoot(t), "cmd")
	executables, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	constructed := map[string][]string{}
	for _, executable := range executables {
		if !executable.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, executable.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range files {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, executable.Name(), entry.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || !strings.HasPrefix(selector.Sel.Name, "New") {
					return true
				}
				if owner, ok := selector.X.(*ast.Ident); ok {
					constructed[executable.Name()] = append(constructed[executable.Name()], owner.Name+"."+selector.Sel.Name)
				}
				return true
			})
		}
	}
	return constructed
}
