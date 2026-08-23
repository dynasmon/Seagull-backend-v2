package rulefile_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
)

func TestEveryRuleFileUnderTheTreeIsRead(t *testing.T) {
	tree := fstest.MapFS{
		"packs/network/scan.yml":  file(named("network.port_scan")),
		"packs/core/auth.yaml":    file(named("ssh.failed_password")),
		"packs/core/session.yml":  file(named("ssh.session_opened"), named("ssh.session_closed")),
		"packs/core/README.md":    file("not a rule file at all"),
		"packs/core/auth.yml.bak": file("schema_version: 99"),
	}

	programs, err := rulefile.Read(tree)
	if err != nil {
		t.Fatalf("a tree that should be read was refused: %v", err)
	}

	read := make([]detection.ID, 0, len(programs))
	for _, program := range programs {
		read = append(read, program.Rule().ID)
	}
	written := []detection.ID{"ssh.failed_password", "ssh.session_opened", "ssh.session_closed", "network.port_scan"}
	if len(read) != len(written) {
		t.Fatalf("the tree was read as %v", read)
	}
	for index, id := range written {
		if read[index] != id {
			t.Errorf("the tree was read as %v and should have been read as %v", read, written)
			break
		}
	}
}

// A ruleset is loaded whole or not at all: half of one is a detection surface
// nobody asked for, and the operator who has to fix a file needs to see every
// file that is wrong rather than the first.
func TestOneBrokenFileDoesNotHideAnother(t *testing.T) {
	tree := fstest.MapFS{
		"packs/a.yml": file(named("a.rule")),
		"packs/b.yml": file(strings.Replace(named("b.rule"), "class: authentication", "class: network", 1)),
		"packs/c.yml": file(strings.Replace(named("c.rule"), "severity: medium", "severity: urgent", 1)),
	}

	programs, err := rulefile.Read(tree)
	if err == nil {
		t.Fatal("a tree with two broken files was read")
	}
	if programs != nil {
		t.Error("a tree that was refused still gave back rules")
	}
	for _, source := range []string{"packs/b.yml", "packs/c.yml"} {
		if !strings.Contains(err.Error(), source) {
			t.Errorf("the refusal does not mention %s: %v", source, err)
		}
	}
	if strings.Contains(err.Error(), "packs/a.yml") {
		t.Errorf("the refusal blames a file that is fine: %v", err)
	}
}

func TestTwoFilesCannotShareARuleId(t *testing.T) {
	tree := fstest.MapFS{
		"packs/a.yml": file(named("a.rule")),
		"packs/b.yml": file(named("a.rule")),
	}

	_, err := rulefile.Read(tree)
	if err == nil {
		t.Fatal("two files sharing a rule id were read")
	}
	if !strings.Contains(err.Error(), "packs/b.yml") || !strings.Contains(err.Error(), "is also the id of a rule in packs/a.yml") {
		t.Errorf("the refusal reads %v", err)
	}
}

func TestATreeWithNoRuleFilesHoldsNoRules(t *testing.T) {
	programs, err := rulefile.Read(fstest.MapFS{"packs/README.md": file("nothing here")})
	if err != nil {
		t.Fatalf("a tree with no rule files was refused: %v", err)
	}
	if len(programs) != 0 {
		t.Errorf("a tree with no rule files held %d rules", len(programs))
	}
}

func file(lines ...string) *fstest.MapFile {
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "  - id:") {
		return &fstest.MapFile{Data: []byte(strings.Join(lines, "\n"))}
	}
	return &fstest.MapFile{Data: []byte("schema_version: 1\nrules:\n" + strings.Join(lines, "") + "\n")}
}

func named(id detection.ID) string {
	return `  - id: ` + string(id) + `
    revision: 1
    name: A name
    description: A description.
    class: authentication
    severity: medium
    status: active
    match: {field: event_id, present: true}
`
}
