package architecture_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const githubActions = 15368

var (
	imageByDigest = regexp.MustCompile(`^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	actionByHash  = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	declaredGo    = regexp.MustCompile(`(?m)^toolchain go(\S+)$`)
	builtWithGo   = regexp.MustCompile(`(?m)^FROM golang:(\d+\.\d+\.\d+)-`)
)

type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Name  string `yaml:"name"`
		Steps []struct {
			Uses string            `yaml:"uses"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func read(t *testing.T, path ...string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(append([]string{moduleRoot(t)}, path...)...))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func workflows(t *testing.T) map[string]workflow {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(moduleRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no workflow was found")
	}
	found := map[string]workflow{}
	for _, file := range files {
		name := filepath.Base(file)
		var parsed workflow
		if err := yaml.Unmarshal(read(t, ".github", "workflows", name), &parsed); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found[name] = parsed
	}
	return found
}

func TestEveryImageIsNamedByItsDigest(t *testing.T) {
	var named []string
	for _, file := range []string{"compose.yaml", "compose.test.yaml"} {
		var compose struct {
			Services map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(read(t, "deploy", file), &compose); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, service := range compose.Services {
			if service.Image != "" {
				named = append(named, service.Image)
			}
		}
	}
	for line := range strings.Lines(string(read(t, "deploy", "Dockerfile"))) {
		if fields := strings.Fields(line); len(fields) > 1 && fields[0] == "FROM" && fields[1] != "scratch" {
			named = append(named, fields[1])
		}
	}
	if len(named) < 5 {
		t.Fatalf("found %d images, which is fewer than the platform runs on", len(named))
	}
	for _, image := range named {
		if !imageByDigest.MatchString(image) {
			t.Errorf("%s is named by a tag, which a registry can move: name it by its digest", image)
		}
	}
}

func TestEveryActionIsNamedByItsCommit(t *testing.T) {
	for name, parsed := range workflows(t) {
		for id, job := range parsed.Jobs {
			for _, step := range job.Steps {
				if step.Uses != "" && !actionByHash.MatchString(step.Uses) {
					t.Errorf("%s, job %s: %s is named by a tag, which its owner can move: name it by its commit", name, id, step.Uses)
				}
			}
		}
	}
}

func TestAWorkflowWritesNothingUnlessAJobAsks(t *testing.T) {
	for name, parsed := range workflows(t) {
		if want := map[string]string{"contents": "read"}; !maps.Equal(parsed.Permissions, want) {
			t.Errorf("%s grants %v to every job, want %v", name, parsed.Permissions, want)
		}
	}
}

func TestOneToolchainBuildsTheModule(t *testing.T) {
	declared := declaredGo.FindSubmatch(read(t, "go.mod"))
	if declared == nil {
		t.Fatal("go.mod names no toolchain")
	}
	built := builtWithGo.FindSubmatch(read(t, "deploy", "Dockerfile"))
	if built == nil {
		t.Fatal("deploy/Dockerfile builds on no versioned golang image")
	}
	if string(declared[1]) != string(built[1]) {
		t.Errorf("go.mod names go%s and the images are built with go%s", declared[1], built[1])
	}
	for name, parsed := range workflows(t) {
		for id, job := range parsed.Jobs {
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
					continue
				}
				if step.With["go-version-file"] != "go.mod" || step.With["go-version"] != "" {
					t.Errorf("%s, job %s: Go is chosen by %v rather than by go.mod", name, id, step.With)
				}
			}
		}
	}
}

func TestEveryJobIsRequiredOnMain(t *testing.T) {
	var ruleset struct {
		BypassActors []any `json:"bypass_actors"`
		Rules        []struct {
			Type       string `json:"type"`
			Parameters struct {
				Required []struct {
					Context       string `json:"context"`
					IntegrationID int    `json:"integration_id"`
				} `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(read(t, ".github", "rulesets", "main.json"), &ruleset); err != nil {
		t.Fatal(err)
	}
	if len(ruleset.BypassActors) > 0 {
		t.Errorf("%d actors may bypass the rules of main, want none", len(ruleset.BypassActors))
	}

	var required, types []string
	for _, rule := range ruleset.Rules {
		types = append(types, rule.Type)
		for _, check := range rule.Parameters.Required {
			required = append(required, check.Context)
			if check.IntegrationID != githubActions {
				t.Errorf("%q may be reported by anything but GitHub Actions", check.Context)
			}
		}
	}
	for _, rule := range []string{"deletion", "non_fast_forward", "pull_request", "required_status_checks"} {
		if !slices.Contains(types, rule) {
			t.Errorf("main is not held by the rule %s", rule)
		}
	}

	declared := workflows(t)
	var jobs []string
	for _, name := range []string{"ci.yml", "codeql.yml"} {
		for _, job := range declared[name].Jobs {
			jobs = append(jobs, job.Name)
		}
	}
	slices.Sort(jobs)
	slices.Sort(required)
	if !slices.Equal(jobs, required) {
		t.Errorf("the jobs are %q and main requires %q", jobs, required)
	}
}
