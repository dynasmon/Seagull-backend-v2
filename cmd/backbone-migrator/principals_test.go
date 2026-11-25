package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func granted(components ...broker.Component) []broker.Grant {
	grants := make([]broker.Grant, 0, len(components))
	for _, component := range components {
		grants = append(grants, broker.Grant{Component: component})
	}
	return grants
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEveryComponentsPasswordIsReadFromTheFileNamedAfterIt(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "event-writer"), "first password\n")
	write(t, filepath.Join(directory, "alert-writer"), "second password")
	write(t, filepath.Join(directory, "unrelated"), "")

	read, err := passwords(directory, granted(broker.EventWriter, broker.AlertWriter))
	if err != nil {
		t.Fatalf("read the passwords: %v", err)
	}
	if read[broker.EventWriter].Reveal() != "first password" || read[broker.AlertWriter].Reveal() != "second password" || len(read) != 2 {
		t.Errorf("read %d passwords", len(read))
	}
}

func TestAMountedSecretIsReadThroughItsLinks(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "..2026_11_25_15_30_00.1", "event-writer"), "mounted")
	if err := os.Symlink("..2026_11_25_15_30_00.1", filepath.Join(directory, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "event-writer"), filepath.Join(directory, "event-writer")); err != nil {
		t.Fatal(err)
	}

	read, err := passwords(directory, granted(broker.EventWriter))
	if err != nil || read[broker.EventWriter].Reveal() != "mounted" {
		t.Fatalf("read %v, %v", read, err)
	}
}

func TestAPasswordMissingEmptyOrOutsideTheDirectoryIsRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere")
	write(t, outside, "a password from somewhere else")

	for name, prepare := range map[string]func(directory string){
		"missing": func(string) {},
		"empty":   func(directory string) { write(t, filepath.Join(directory, "event-writer"), " \n") },
		"outside": func(directory string) {
			if err := os.Symlink(outside, filepath.Join(directory, "event-writer")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		directory := t.TempDir()
		prepare(directory)
		if read, err := passwords(directory, granted(broker.EventWriter)); err == nil {
			t.Errorf("%s: read %d passwords", name, len(read))
		} else if strings.Contains(err.Error(), "somewhere else") {
			t.Errorf("%s: the refusal carries the password: %v", name, err)
		}
	}
}

func loaded(t *testing.T, environment map[string]string) (configuration, error) {
	t.Helper()
	base := map[string]string{"SEAGULL_BACKBONE_BROKERS": "127.0.0.1:9092"}
	for key, value := range environment {
		base[key] = value
	}
	return load(config.New(func(key string) (string, bool) {
		value, given := base[key]
		return value, given
	}))
}

func TestABackboneThatAuthenticatesIsGivenItsPrincipalsAndOneThatDoesNotIsGivenNone(t *testing.T) {
	directory := t.TempDir()
	authenticated := map[string]string{
		"SEAGULL_BACKBONE_SASL_MECHANISM": "scram-sha-256",
		"SEAGULL_BACKBONE_SASL_USER":      "superuser",
		"SEAGULL_BACKBONE_SASL_PASSWORD":  "superuser password",
	}
	if _, err := loaded(t, authenticated); err == nil || !strings.Contains(err.Error(), "SEAGULL_BACKBONE_PRINCIPALS_DIR") {
		t.Errorf("an authenticating backbone without principals: %v", err)
	}
	authenticated["SEAGULL_BACKBONE_PRINCIPALS_DIR"] = directory
	if settings, err := loaded(t, authenticated); err != nil || settings.principals != directory {
		t.Errorf("an authenticating backbone with principals: %v", err)
	}
	unauthenticated := map[string]string{
		"SEAGULL_BACKBONE_SASL_MECHANISM": "none",
		"SEAGULL_BACKBONE_TLS":            "false",
		"SEAGULL_BACKBONE_DURABILITY":     "development",
		"SEAGULL_BACKBONE_PRINCIPALS_DIR": directory,
	}
	if _, err := loaded(t, unauthenticated); err == nil {
		t.Error("principals were accepted for a backbone that authenticates nobody")
	}
	delete(unauthenticated, "SEAGULL_BACKBONE_PRINCIPALS_DIR")
	if _, err := loaded(t, unauthenticated); err != nil {
		t.Errorf("a development backbone: %v", err)
	}
}
