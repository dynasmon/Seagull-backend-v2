package architecture_test

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const backboneAdministrator = "backbone-migrator"

var (
	builtComponents = regexp.MustCompile(`(?m)^COMPONENTS := (.+)$`)
	declaredService = regexp.MustCompile(`serviceName\s*=\s*"([^"]+)"`)
)

func TestEveryComponentThatReachesTheBackboneIsGrantedAsItself(t *testing.T) {
	built := builtComponents.FindSubmatch(read(t, "Makefile"))
	if built == nil {
		t.Fatal("the Makefile declares no COMPONENTS")
	}
	components := strings.Fields(string(built[1]))

	reaching := map[string]bool{}
	for _, listed := range packages(t) {
		name, executable := strings.CutPrefix(listed.path, modulePath+"/cmd/")
		if executable && slices.Contains(listed.imports, modulePath+"/internal/broker") {
			reaching[path.Base(name)] = true
		}
	}

	topology := broker.LoadTopology(config.New(func(string) (string, bool) { return "", false }))
	granted := map[string]bool{}
	for _, grant := range topology.Grants() {
		granted[string(grant.Component)] = true
		if !slices.Contains(components, string(grant.Component)) {
			t.Errorf("%s is granted on the backbone and the Makefile builds no component of that name", grant.Component)
		}
	}

	for _, component := range components {
		switch {
		case component == backboneAdministrator && granted[component]:
			t.Errorf("%s administers the backbone and holds no grant of its own", component)
		case component == backboneAdministrator:
		case reaching[component] && !granted[component]:
			t.Errorf("%s reaches the backbone and is granted nothing there, so the broker would refuse it everything", component)
		case !reaching[component] && granted[component]:
			t.Errorf("%s is granted on the backbone and never reaches it", component)
		}

		service := declaredService.FindSubmatch(read(t, "cmd", component, "config.go"))
		if service == nil || string(service[1]) != component {
			t.Errorf("cmd/%s declares no service named %s, and a component authenticates and consumes under its own name", component, component)
		}
	}
	for component := range reaching {
		if !slices.Contains(components, component) {
			t.Errorf("cmd/%s reaches the backbone and the Makefile does not build it", component)
		}
	}
}

func TestTheGrantsAreHeldAgainstTheBackboneTheStackRuns(t *testing.T) {
	images := map[string]string{}
	for file, service := range map[string]string{"compose.yaml": "redpanda", "compose.test.yaml": "redpanda-secured"} {
		var compose struct {
			Services map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(read(t, "deploy", file), &compose); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		images[service] = compose.Services[service].Image
	}
	if images["redpanda-secured"] == "" || images["redpanda-secured"] != images["redpanda"] {
		t.Errorf("the grants are held against %q and the stack runs %q", images["redpanda-secured"], images["redpanda"])
	}
	if !strings.Contains(string(read(t, "Makefile")), "up -d --wait redpanda clickhouse postgres redpanda-secured") {
		t.Error("make test-integration does not start the secured backbone, so the suite holding the grants would skip")
	}
}

func TestEveryComponentThatReachesTheBackboneObservesWhatItIsRefused(t *testing.T) {
	topology := broker.LoadTopology(config.New(func(string) (string, bool) { return "", false }))
	for _, grant := range topology.Grants() {
		main := string(read(t, "cmd", string(grant.Component), "main.go"))
		for _, wiring := range []string{
			"denials := broker.NewDenials(platform.Metrics())",
			"settings.security = settings.security.Observed(denials)",
			`platform.Health().Register("backbone-access", denials.Check)`,
		} {
			if !strings.Contains(main, wiring) {
				t.Errorf("cmd/%s/main.go lacks %s, so what the backbone refuses it is neither counted nor reported", grant.Component, wiring)
			}
		}
		observed := strings.Index(main, "settings.security = settings.security.Observed(denials)")
		if first := strings.Index(main, "settings.security,"); first >= 0 && observed > first {
			t.Errorf("cmd/%s/main.go builds a backbone client before it observes what the backbone refuses", grant.Component)
		}
	}
}
