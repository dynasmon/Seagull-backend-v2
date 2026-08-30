package postgres

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
	version uint64
	name    string
	body    string
}

func (m migration) String() string { return fmt.Sprintf("%04d_%s", m.version, m.name) }

var migrations = mustLoad()

func mustLoad() []migration {
	loaded, err := load()
	if err != nil {
		panic("postgres: " + err.Error())
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
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("%s is empty", entry.Name())
		}
		loaded = append(loaded, migration{version: version, name: name, body: string(body)})
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
