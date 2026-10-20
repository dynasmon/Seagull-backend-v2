package clickhouse

import (
	"fmt"
)

type rebuild struct {
	table   string
	staging string
}

// A rebuild resumes from what the store holds rather than from what the
// migration remembers, so its migration holds nothing but the table it creates.
func (r rebuild) check(entry migration) error {
	if len(entry.statements) != 1 {
		return fmt.Errorf("a rebuild of %s is the one statement creating %s, and %s has %d",
			r.table, r.staging, entry, len(entry.statements))
	}
	if _, creates := createTableBody(entry.statements[0], r.staging); !creates {
		return fmt.Errorf("a rebuild of %s creates %s, which %s does not", r.table, r.staging, entry)
	}
	if _, err := declaredSortingKey(entry.statements[0]); err != nil {
		return fmt.Errorf("%s: %w", r.staging, err)
	}
	return nil
}
