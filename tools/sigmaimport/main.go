package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/sigma"
)

func main() {
	input := flag.String("input", "", "a Sigma rule file, or a directory of them")
	output := flag.String("output", "", "the Seagull rule file to write (default: standard output)")
	strict := flag.Bool("strict", false, "refuse the whole import when any rule cannot be translated")
	flag.Parse()

	if err := run(*input, *output, *strict); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(input, output string, strict bool) error {
	if input == "" {
		return errors.New("sigmaimport: -input names the Sigma rule or directory to translate")
	}

	documents, err := documentsUnder(input)
	if err != nil {
		return err
	}
	if len(documents) == 0 {
		return fmt.Errorf("sigmaimport: %s holds no Sigma document", input)
	}

	rules, refusals := translated(documents)
	for _, refusal := range refusals {
		fmt.Fprintln(os.Stderr, refusal)
	}
	switch {
	case strict && len(refusals) > 0:
		return fmt.Errorf("sigmaimport: %d of %d documents were refused, and -strict imports all of them or none", len(refusals), len(documents))
	case len(rules) == 0:
		return fmt.Errorf("sigmaimport: nothing translated, and %d of %d documents were refused", len(refusals), len(documents))
	}

	written, err := rulefile.Write(rules)
	if err != nil {
		return fmt.Errorf("sigmaimport: %w", err)
	}
	if err := emit(output, written); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "sigmaimport: %d of %d documents translated into draft rules; write the cases each one is expected to hold before shipping it\n",
		len(rules), len(documents))
	return nil
}

func translated(documents []string) ([]detection.Rule, []error) {
	var (
		rules    []detection.Rule
		refusals []error
	)
	for _, name := range documents {
		data, err := os.ReadFile(name)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		rule, err := sigma.Translate(name, data)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, refusals
}

func documentsUnder(input string) ([]string, error) {
	described, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("sigmaimport: %w", err)
	}
	if !described.IsDir() {
		return []string{input}, nil
	}

	var documents []string
	walked := filepath.WalkDir(input, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			documents = append(documents, name)
		}
		return nil
	})
	if walked != nil {
		return nil, fmt.Errorf("sigmaimport: %w", walked)
	}
	sort.Strings(documents)
	return documents, nil
}

func emit(output string, written []byte) error {
	if output == "" {
		_, err := os.Stdout.Write(written)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return fmt.Errorf("sigmaimport: %w", err)
	}
	if err := os.WriteFile(output, written, 0o644); err != nil {
		return fmt.Errorf("sigmaimport: %w", err)
	}
	return nil
}
