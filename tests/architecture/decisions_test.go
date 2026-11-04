package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	decisionFile    = regexp.MustCompile(`^(\d{4})-[a-z0-9-]+\.md$`)
	decisionHeading = regexp.MustCompile(`\A# (\d+)\. (.+)\n`)
	indexedDecision = regexp.MustCompile(`(?m)^- \[(\d+)\. (.+)\]\(([^)\s]+)\)$`)
	linkedTarget    = regexp.MustCompile(`\]\(([^)#\s]+)(?:#[^)\s]*)?\)`)
	amendedBy       = regexp.MustCompile(`(?m)^> Amended by \[ADR (\d+)\]\(([^)\s]+)\)`)
)

type decision struct {
	file    string
	title   string
	content string
}

func decisions(t *testing.T) map[int]decision {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(moduleRoot(t), "docs", "decisions"))
	if err != nil {
		t.Fatal(err)
	}
	found := map[int]decision{}
	for _, entry := range entries {
		named := decisionFile.FindStringSubmatch(entry.Name())
		if named == nil {
			continue
		}
		number, _ := strconv.Atoi(named[1])
		content := string(read(t, "docs", "decisions", entry.Name()))
		heading := decisionHeading.FindStringSubmatch(content)
		if heading == nil || heading[1] != strconv.Itoa(number) {
			t.Errorf("%s does not open with its number and its title", entry.Name())
			continue
		}
		if held, taken := found[number]; taken {
			t.Errorf("%s and %s are both decision %d", held.file, entry.Name(), number)
		}
		found[number] = decision{file: entry.Name(), title: heading[2], content: content}
	}
	if len(found) == 0 {
		t.Fatal("no decision record was found")
	}
	return found
}

func TestEveryDecisionIsIndexedUnderItsOwnTitle(t *testing.T) {
	recorded := decisions(t)
	var listed []int
	for _, entry := range indexedDecision.FindAllStringSubmatch(string(read(t, "docs", "decisions", "README.md")), -1) {
		number, _ := strconv.Atoi(entry[1])
		listed = append(listed, number)
		held, known := recorded[number]
		switch {
		case !known:
			t.Errorf("the index lists decision %d, and no record of it exists", number)
		case entry[3] != held.file:
			t.Errorf("the index links decision %d to %s, and its record is %s", number, entry[3], held.file)
		case entry[2] != held.title:
			t.Errorf("the index titles decision %d %q, and its record %q", number, entry[2], held.title)
		}
	}
	if !slices.IsSorted(listed) {
		t.Errorf("the index lists the decisions out of order: %v", listed)
	}
	for number, held := range recorded {
		if !slices.Contains(listed, number) {
			t.Errorf("%s is missing from the index", held.file)
		}
	}
}

func TestEveryLinkOfADecisionReachesAFile(t *testing.T) {
	for _, held := range decisions(t) {
		for _, link := range linkedTarget.FindAllStringSubmatch(held.content, -1) {
			if strings.Contains(link[1], "://") {
				continue
			}
			if _, err := os.Stat(filepath.Join(moduleRoot(t), "docs", "decisions", link[1])); err != nil {
				t.Errorf("%s links %s, which does not exist", held.file, link[1])
			}
		}
	}
}

func TestADecisionIsAmendedOnlyByALaterOneThatNamesIt(t *testing.T) {
	recorded := decisions(t)
	for number, held := range recorded {
		for _, note := range amendedBy.FindAllStringSubmatch(held.content, -1) {
			by, _ := strconv.Atoi(note[1])
			amending, known := recorded[by]
			switch {
			case !known || note[2] != amending.file:
				t.Errorf("%s says decision %d amends it, at %s, which is not that record", held.file, by, note[2])
			case by <= number:
				t.Errorf("%s says decision %d amends it, which came before it", held.file, by)
			case !strings.Contains(amending.content, "]("+held.file+")"):
				t.Errorf("%s says %s amends it, and %s never names it", held.file, amending.file, amending.file)
			}
		}
	}
}
