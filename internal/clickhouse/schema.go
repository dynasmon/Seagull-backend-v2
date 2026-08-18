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

//go:embed schema/*.sql
var files embed.FS

const directory = "schema"

type migration struct {
	version    uint64
	name       string
	statements []string
}

func (m migration) String() string { return fmt.Sprintf("%04d_%s", m.version, m.name) }

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
		parsed := statements(string(body))
		for _, statement := range parsed {
			if !isIdempotent(statement) {
				return nil, fmt.Errorf("%s contains a statement that cannot be applied twice: %.60s", entry.Name(), statement)
			}
		}
		loaded = append(loaded, migration{version: version, name: name, statements: parsed})
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

// A migration may restart before its ledger row is written.
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

func declaredColumns(table string) ([]string, error) {
	return declaredColumnsIn(migrations, table)
}

func declaredColumnsIn(history []migration, table string) ([]string, error) {
	var columns []string
	created := false

	for _, applied := range history {
		for _, statement := range applied.statements {
			body, found := createTableBody(statement, table)
			if found {
				if created {
					continue
				}
				columns = columnNames(body)
				if len(columns) == 0 {
					return nil, fmt.Errorf("the create statement for %s declares no columns", table)
				}
				created = true
				continue
			}

			target, actions, altered, err := alterTable(statement)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", applied, err)
			}
			if !altered || !strings.EqualFold(target, table) {
				continue
			}
			if !created {
				return nil, fmt.Errorf("%s alters %s before it is created", applied, table)
			}
			for _, action := range actions {
				columns, err = applyColumnAction(columns, action)
				if err != nil {
					return nil, fmt.Errorf("read %s: %w", applied, err)
				}
			}
		}
	}
	if !created {
		return nil, fmt.Errorf("no embedded migration creates %s", table)
	}
	return columns, nil
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
	if !strings.EqualFold(identifier(fields[len(fields)-1]), table) {
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
				columns = append(columns, identifier(strings.Trim(fields[0], ",")))
			}
		}
		depth += strings.Count(line, "(") - strings.Count(line, ")")
	}
	return columns
}

type columnAction struct {
	kind        string
	name        string
	replacement string
	after       string
	first       bool
	guarded     bool
}

func isIdempotent(statement string) bool {
	tokens, err := sqlTokens(statement)
	if err != nil {
		return false
	}
	switch {
	case hasPrefix(tokens, "CREATE", "TABLE", "IF", "NOT", "EXISTS"),
		hasPrefix(tokens, "CREATE", "VIEW", "IF", "NOT", "EXISTS"),
		hasPrefix(tokens, "CREATE", "MATERIALIZED", "VIEW", "IF", "NOT", "EXISTS"):
		return true
	}

	_, actions, altered, err := alterTableTokens(tokens)
	if err != nil || !altered {
		return false
	}
	for _, tokens := range actions {
		action, err := parseColumnAction(tokens)
		if err != nil || !action.guarded {
			return false
		}
	}
	return true
}

func alterTable(statement string) (string, [][]string, bool, error) {
	tokens, err := sqlTokens(statement)
	if err != nil {
		return "", nil, false, err
	}
	return alterTableTokens(tokens)
}

func alterTableTokens(tokens []string) (string, [][]string, bool, error) {
	if !hasPrefix(tokens, "ALTER", "TABLE") {
		return "", nil, false, nil
	}

	index := 2
	if hasPrefix(tokens[index:], "IF", "EXISTS") {
		index += 2
	}
	if index >= len(tokens) || tokens[index] == "," {
		return "", nil, true, errors.New("ALTER TABLE has no table name")
	}
	table := identifier(tokens[index])
	index++
	if hasPrefix(tokens[index:], "ON", "CLUSTER") {
		index += 2
		if index >= len(tokens) || tokens[index] == "," {
			return "", nil, true, errors.New("ALTER TABLE has no cluster name")
		}
		index++
	}
	if index >= len(tokens) {
		return "", nil, true, errors.New("ALTER TABLE has no action")
	}

	var actions [][]string
	start := index
	for index <= len(tokens) {
		if index == len(tokens) || tokens[index] == "," {
			if start == index {
				return "", nil, true, errors.New("ALTER TABLE has an empty action")
			}
			actions = append(actions, tokens[start:index])
			start = index + 1
		}
		index++
	}
	return table, actions, true, nil
}

func parseColumnAction(tokens []string) (columnAction, error) {
	if len(tokens) < 3 || !strings.EqualFold(tokens[1], "COLUMN") {
		return columnAction{}, fmt.Errorf("unsupported ALTER TABLE action: %s", strings.Join(tokens, " "))
	}

	action := columnAction{kind: strings.ToUpper(tokens[0])}
	index := 2
	switch action.kind {
	case "ADD":
		if hasPrefix(tokens[index:], "IF", "NOT", "EXISTS") {
			action.guarded = true
			index += 3
		}
	case "DROP", "RENAME":
		if hasPrefix(tokens[index:], "IF", "EXISTS") {
			action.guarded = true
			index += 2
		}
	default:
		return columnAction{}, fmt.Errorf("unsupported ALTER TABLE action: %s", strings.Join(tokens, " "))
	}
	if index >= len(tokens) {
		return columnAction{}, fmt.Errorf("%s COLUMN has no column name", action.kind)
	}
	action.name = identifier(tokens[index])
	index++

	switch action.kind {
	case "ADD":
		for offset := index; offset < len(tokens); offset++ {
			switch {
			case strings.EqualFold(tokens[offset], "FIRST") && offset == len(tokens)-1:
				action.first = true
			case strings.EqualFold(tokens[offset], "AFTER") && offset == len(tokens)-2:
				action.after = identifier(tokens[offset+1])
			}
		}
	case "DROP":
		if index != len(tokens) {
			return columnAction{}, fmt.Errorf("DROP COLUMN has unexpected tokens: %s", strings.Join(tokens[index:], " "))
		}
	case "RENAME":
		if index+2 != len(tokens) || !strings.EqualFold(tokens[index], "TO") {
			return columnAction{}, errors.New("RENAME COLUMN must name exactly one replacement")
		}
		action.replacement = identifier(tokens[index+1])
	}
	return action, nil
}

func applyColumnAction(columns []string, tokens []string) ([]string, error) {
	action, err := parseColumnAction(tokens)
	if err != nil {
		return nil, err
	}
	index := slices.Index(columns, action.name)

	switch action.kind {
	case "ADD":
		if index >= 0 {
			if action.guarded {
				return columns, nil
			}
			return nil, fmt.Errorf("ADD COLUMN repeats %s", action.name)
		}
		at := len(columns)
		if action.first {
			at = 0
		} else if action.after != "" {
			after := slices.Index(columns, action.after)
			if after < 0 {
				return nil, fmt.Errorf("ADD COLUMN %s follows missing column %s", action.name, action.after)
			}
			at = after + 1
		}
		columns = slices.Insert(columns, at, action.name)
	case "DROP":
		if index < 0 {
			if action.guarded {
				return columns, nil
			}
			return nil, fmt.Errorf("DROP COLUMN names missing column %s", action.name)
		}
		columns = slices.Delete(columns, index, index+1)
	case "RENAME":
		if index < 0 {
			if action.guarded {
				return columns, nil
			}
			return nil, fmt.Errorf("RENAME COLUMN names missing column %s", action.name)
		}
		if slices.Contains(columns, action.replacement) {
			return nil, fmt.Errorf("RENAME COLUMN targets existing column %s", action.replacement)
		}
		columns[index] = action.replacement
	}
	return columns, nil
}

func hasPrefix(tokens []string, prefix ...string) bool {
	if len(tokens) < len(prefix) {
		return false
	}
	for index := range prefix {
		if !strings.EqualFold(tokens[index], prefix[index]) {
			return false
		}
	}
	return true
}

func identifier(token string) string {
	return strings.Trim(token, "`\"")
}

func sqlTokens(statement string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	depth := 0
	var quote byte

	flush := func() {
		if token.Len() > 0 {
			tokens = append(tokens, token.String())
			token.Reset()
		}
	}

	for index := 0; index < len(statement); index++ {
		character := statement[index]
		if quote != 0 {
			token.WriteByte(character)
			if character == '\\' && index+1 < len(statement) {
				index++
				token.WriteByte(statement[index])
				continue
			}
			if character == quote {
				if index+1 < len(statement) && statement[index+1] == quote {
					index++
					token.WriteByte(statement[index])
				} else {
					quote = 0
				}
			}
			continue
		}

		switch character {
		case '\'', '"', '`':
			quote = character
			token.WriteByte(character)
		case '(', '[', '{':
			depth++
			token.WriteByte(character)
		case ')', ']', '}':
			if depth == 0 {
				return nil, errors.New("SQL contains an unmatched closing delimiter")
			}
			depth--
			token.WriteByte(character)
		case ',':
			if depth == 0 {
				flush()
				tokens = append(tokens, ",")
			} else {
				token.WriteByte(character)
			}
		case ' ', '\t', '\r', '\n':
			if depth == 0 {
				flush()
			} else {
				token.WriteByte(character)
			}
		default:
			token.WriteByte(character)
		}
	}
	if quote != 0 || depth != 0 {
		return nil, errors.New("SQL contains an unterminated quote or delimiter")
	}
	flush()
	return tokens, nil
}
