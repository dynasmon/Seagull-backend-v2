package architecture_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// The engine detects from its rule tree until it has read the log, and the
// control plane records that tree as the installation's first publication
// (ADR 51). Given two trees, an installation would record one and detect from
// the other.
func TestTheEngineAndTheControlPlaneAreGivenOneRuleTree(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}

	mounted := map[string]string{}
	for _, name := range []string{"analysis-engine", "control-api"} {
		service, declared := compose.Services[name]
		if !declared {
			t.Fatalf("compose.yaml declares no %s", name)
		}
		tree := service.Environment["SEAGULL_DETECTION_RULES"]
		if tree == "" {
			t.Errorf("%s is not told where the rule tree is", name)
			continue
		}
		for _, volume := range service.Volumes {
			if source, target, _ := strings.Cut(volume, ":"); strings.TrimSuffix(target, ":ro") == tree {
				mounted[name] = source
			}
		}
		if mounted[name] == "" {
			t.Errorf("%s reads its rules from %s and nothing is mounted there", name, tree)
		}
	}
	if mounted["analysis-engine"] != mounted["control-api"] {
		t.Errorf("the engine starts on %q and the control plane records %q", mounted["analysis-engine"], mounted["control-api"])
	}
}

// A host that restarts brings the stack back by itself, so recovering from a
// reboot never runs make up, which minted the development material again until
// 2026-11-20; a migrator runs once and stays stopped.
func TestEveryProcessOfTheStackComesBackAfterTheHostRestarts(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Restart string `yaml:"restart"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	if len(compose.Services) < 10 {
		t.Fatalf("compose.yaml declares %d services, fewer than the platform runs", len(compose.Services))
	}
	for name, service := range compose.Services {
		wanted := "unless-stopped"
		if strings.HasSuffix(name, "-migrator") {
			wanted = "no"
		}
		if service.Restart != wanted {
			t.Errorf("%s restarts %q, and it has to restart %q", name, service.Restart, wanted)
		}
	}
}

// Redpanda runs on data written by its own feature release or the one before
// it, so the backbone image moves one logical version at a time: on 2026-11-02
// it moved six, and every development volume older than that stopped starting.
func TestTheBackboneMovesOneLogicalVersionAtATime(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	var images []string
	var versions []int
	for line := range strings.Lines(string(read(t, "deploy", "redpanda-upgrade-path"))) {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		version, err := strconv.Atoi(fields[len(fields)-1])
		if len(fields) != 2 || err != nil {
			t.Fatalf("%q is not an image and the logical version it runs", strings.TrimSpace(line))
		}
		if !imageByDigest.MatchString(fields[0]) {
			t.Errorf("%s is named by a tag, which a registry can move: name it by its digest", fields[0])
		}
		if len(versions) > 0 && version != versions[len(versions)-1]+1 {
			t.Errorf("%s runs logical version %d after %d, and a release reads data at most one behind it", fields[0], version, versions[len(versions)-1])
		}
		images, versions = append(images, fields[0]), append(versions, version)
	}
	if len(images) < 2 {
		t.Fatalf("the upgrade path holds %d releases, and the backbone has run more than one", len(images))
	}
	if running := compose.Services["redpanda"].Image; running != images[len(images)-1] {
		t.Errorf("deploy/compose.yaml runs %s, and the upgrade path ends at %s", running, images[len(images)-1])
	}
}

func TestTheDevelopmentStackForwardsWhatTheFleetIsRunWith(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	for service, settings := range map[string][]string{
		"ingest-gateway": {"SEAGULL_GATEWAY_STATUS_INTERVAL"},
		"control-api":    {"SEAGULL_CONTROL_API_AGENT_POLICY_SIGNERS", "SEAGULL_CONTROL_API_AGENT_UPDATE_ROOT", "SEAGULL_CONTROL_API_FLEET_INTERVAL"},
	} {
		for _, setting := range settings {
			if forwarded := compose.Services[service].Environment[setting]; forwarded != "${"+setting+":-}" {
				t.Errorf("%s is given %s as %q, so make up cannot set it", service, setting, forwarded)
			}
		}
	}
	if !slices.Contains(compose.Services["control-api"].Volumes, "../.local/signing:/run/signing:ro") {
		t.Error("control-api mounts nothing a policy signer or an update root can be read from")
	}
}

func TestEveryImageTheDevelopmentStackBuildsKnowsItsRevision(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Build struct {
				Args map[string]string `yaml:"args"`
			} `yaml:"build"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(read(t, "deploy", "compose.yaml"), &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	built := 0
	for name, service := range compose.Services {
		if service.Build.Args["COMPONENT"] == "" {
			continue
		}
		built++
		if revision := service.Build.Args["REVISION"]; revision != "${SEAGULL_REVISION:-unknown}" {
			t.Errorf("%s is built with the revision %q, so it reports none it was built from", name, revision)
		}
	}
	if built < 10 {
		t.Fatalf("compose.yaml builds %d images, fewer than the platform runs", built)
	}
	if !strings.Contains(string(read(t, "Makefile")), "SEAGULL_REVISION=$(REVISION) ") {
		t.Error("make up gives the stack it builds no revision")
	}
}
