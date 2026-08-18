package clickhouse

import (
	"cmp"
	"embed"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The containers are built FROM scratch and carry no filesystem to read from.
//
//go:embed schema/*.sql
var files embed.FS

const directory = "schema"

type migration struct {
	version    uint64
	name       string
	statements []string
}

func (m migration) String() string { return fmt.Sprintf("%04d_%s", m.version, m.name) }

// A malformed schema file is a defect in this package, so it fails at startup
// rather than mid-migration.
var migrations = mustLoad()

func mustLoad() []migration {
	loaded, err := load()
	if err != nil {
		panic("clickhouse: " + err.Error())
	}
	return loaded
}

func load() ([]migration, error) {
	entries, err := files.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read the embedded schema: %w", err)
	}

	loaded := make([]migration, 0, len(entries))
	for _, entry := range entries {
		version, name, err := describe(entry.Name())
		if err != nil {
			return nil, err
		}
		body, err := files.ReadFile(path.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		loaded = append(loaded, migration{version: version, name: name, statements: statements(string(body))})
	}

	slices.SortFunc(loaded, func(a, b migration) int { return cmp.Compare(a.version, b.version) })
	for index := 1; index < len(loaded); index++ {
		if loaded[index].version == loaded[index-1].version {
			return nil, fmt.Errorf("two migrations claim version %d", loaded[index].version)
		}
	}
	if len(loaded) == 0 {
		return nil, errors.New("no migrations were embedded")
	}
	return loaded, nil
}

func describe(filename string) (uint64, string, error) {
	trimmed := strings.TrimSuffix(filename, ".sql")
	digits, name, found := strings.Cut(trimmed, "_")
	if !found || name == "" {
		return 0, "", fmt.Errorf("%s is not named <version>_<name>.sql", filename)
	}
	version, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || version == 0 {
		return 0, "", fmt.Errorf("%s does not start with a positive version", filename)
	}
	return version, name, nil
}

// Every statement must be idempotent: ClickHouse runs no DDL transaction, and a
// run interrupted before its ledger row is applied again next time.
func statements(body string) []string {
	var parsed []string
	for _, statement := range strings.Split(uncommented(body), ";") {
		if trimmed := strings.TrimSpace(statement); trimmed != "" {
			parsed = append(parsed, trimmed)
		}
	}
	return parsed
}

func uncommented(statement string) string {
	lines := strings.Split(statement, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// Reads CREATE TABLE only, relying on one column per line with the name first.
// A column added later by ALTER is covered by VerifySchema instead.
func declaredColumns(table string) ([]string, error) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			body, found := createTableBody(statement, table)
			if !found {
				continue
			}
			columns := columnNames(body)
			if len(columns) == 0 {
				return nil, fmt.Errorf("the create statement for %s declares no columns", table)
			}
			return columns, nil
		}
	}
	return nil, fmt.Errorf("no embedded migration creates %s", table)
}

func createTableBody(statement, table string) (string, bool) {
	head, body, found := strings.Cut(statement, "(")
	if !found {
		return "", false
	}
	fields := strings.Fields(strings.ToUpper(head))
	if len(fields) < 3 || fields[0] != "CREATE" || fields[1] != "TABLE" {
		return "", false
	}
	if !strings.EqualFold(fields[len(fields)-1], table) {
		return "", false
	}

	depth := 1
	for index, character := range body {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[:index], true
			}
		}
	}
	return "", false
}

func columnNames(body string) []string {
	var columns []string
	depth := 0
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if depth == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			if fields := strings.Fields(trimmed); len(fields) > 1 {
				columns = append(columns, strings.Trim(fields[0], ","))
			}
		}
		depth += strings.Count(line, "(") - strings.Count(line, ")")
	}
	return columns
}
