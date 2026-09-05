package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Lookup func(key string) (string, bool)

type Parser struct {
	lookup   Lookup
	readFile func(string) ([]byte, error)
	problems map[string]error
}

func New(lookup Lookup) *Parser {
	return &Parser{lookup: lookup, readFile: os.ReadFile, problems: map[string]error{}}
}

func FromEnvironment() *Parser { return New(os.LookupEnv) }

func (p *Parser) Err() error {
	if len(p.problems) == 0 {
		return nil
	}
	keys := make([]string, 0, len(p.problems))
	for key := range p.problems {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	joined := make([]error, 0, len(keys))
	for _, key := range keys {
		joined = append(joined, fmt.Errorf("%s: %w", key, p.problems[key]))
	}
	return fmt.Errorf("invalid configuration: %w", errors.Join(joined...))
}

func (p *Parser) fail(key string, err error) {
	if _, exists := p.problems[key]; !exists {
		p.problems[key] = err
	}
}

// An empty value counts as absent: Compose renders unset variables as empty
// strings, and a silently empty setting is harder to notice than a missing one.
func (p *Parser) raw(key string) (string, bool) {
	if value, ok := p.lookup(key); ok {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed, true
		}
	}
	path, ok := p.lookup(key + "_FILE")
	if !ok {
		return "", false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	content, err := p.readFile(path)
	if err != nil {
		p.fail(key+"_FILE", fmt.Errorf("unreadable: %w", err))
		return "", false
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		p.fail(key+"_FILE", errors.New("file is empty"))
		return "", false
	}
	return trimmed, true
}

func (p *Parser) String(key, fallback string) string {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	return value
}

func (p *Parser) RequiredString(key string) string {
	value, ok := p.raw(key)
	if !ok {
		p.fail(key, errors.New("is required"))
		return ""
	}
	return value
}

func (p *Parser) Secret(key string) Secret {
	value, ok := p.raw(key)
	if !ok {
		return ""
	}
	return Secret(value)
}

func (p *Parser) RequiredSecret(key string) Secret {
	value, ok := p.raw(key)
	if !ok {
		p.fail(key, errors.New("is required"))
		return ""
	}
	return Secret(value)
}

func (p *Parser) Int(key string, fallback, minimum, maximum int) int {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		p.fail(key, fmt.Errorf("%q is not an integer", value))
		return fallback
	}
	if parsed < minimum || parsed > maximum {
		p.fail(key, fmt.Errorf("%d is outside %d..%d", parsed, minimum, maximum))
		return fallback
	}
	return parsed
}

func (p *Parser) Bool(key string, fallback bool) bool {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		p.fail(key, fmt.Errorf("%q is not true or false", value))
		return fallback
	}
	return parsed
}

func (p *Parser) Duration(key string, fallback, minimum, maximum time.Duration) time.Duration {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		p.fail(key, fmt.Errorf("%q is not a duration", value))
		return fallback
	}
	if parsed < minimum || parsed > maximum {
		p.fail(key, fmt.Errorf("%s is outside %s..%s", parsed, minimum, maximum))
		return fallback
	}
	return parsed
}

func (p *Parser) Bytes(key string, fallback, minimum, maximum int64) int64 {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	parsed, err := parseBytes(value)
	if err != nil {
		p.fail(key, err)
		return fallback
	}
	if parsed < minimum || parsed > maximum {
		p.fail(key, fmt.Errorf("%d is outside %d..%d bytes", parsed, minimum, maximum))
		return fallback
	}
	return parsed
}

func (p *Parser) list(key string, fallback []string) []string {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		p.fail(key, errors.New("holds no usable entries"))
		return fallback
	}
	return out
}

func (p *Parser) RequiredList(key string) []string {
	if _, ok := p.raw(key); !ok {
		p.fail(key, errors.New("is required"))
		return nil
	}
	return p.list(key, nil)
}

func (p *Parser) Enum(key, fallback string, allowed ...string) string {
	value, ok := p.raw(key)
	if !ok {
		return fallback
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	p.fail(key, fmt.Errorf("%q is not one of %s", value, strings.Join(allowed, ", ")))
	return fallback
}

func (p *Parser) FilePath(key, fallback string) string {
	value := p.String(key, fallback)
	if value == "" {
		return ""
	}
	if _, err := os.Stat(value); err != nil {
		p.fail(key, fmt.Errorf("path %q is unusable: %w", value, err))
		return ""
	}
	return value
}

func (p *Parser) RequiredFilePath(key string) string {
	value := p.RequiredString(key)
	if value == "" {
		return ""
	}
	if _, err := os.Stat(value); err != nil {
		p.fail(key, fmt.Errorf("path %q is unusable: %w", value, err))
		return ""
	}
	return value
}

func parseBytes(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	units := []struct {
		suffix string
		factor int64
	}{
		{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"B", 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(trimmed, unit.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(trimmed, unit.suffix))
		parsed, err := strconv.ParseInt(number, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a byte size", value)
		}
		if parsed < 0 || parsed > (1<<62)/unit.factor {
			return 0, fmt.Errorf("%q is out of range", value)
		}
		return parsed * unit.factor, nil
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a byte size", value)
	}
	return parsed, nil
}
