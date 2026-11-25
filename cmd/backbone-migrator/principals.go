package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

// One file per component, named after it, in one directory: the shape of a
// Kubernetes Secret mounted as a volume. Only the files of the components
// granted are read, so what else the directory holds is never opened.
func passwords(directory string, grants []broker.Grant) (map[broker.Component]config.Secret, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open the backbone principals: %w", err)
	}
	defer func() { _ = root.Close() }()

	read := make(map[broker.Component]config.Secret, len(grants))
	for _, grant := range grants {
		content, err := root.ReadFile(string(grant.Component))
		if err != nil {
			return nil, fmt.Errorf("read the backbone password of %s: %w", grant.Component, err)
		}
		password := strings.TrimSpace(string(content))
		if password == "" {
			return nil, fmt.Errorf("the backbone password of %s is empty", grant.Component)
		}
		read[grant.Component] = config.Secret(password)
	}
	return read, nil
}
