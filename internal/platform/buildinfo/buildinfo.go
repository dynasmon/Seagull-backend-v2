package buildinfo

import (
	"runtime"
	"runtime/debug"
	"sync"
)

var (
	version  = "dev"
	revision = ""
)

type Info struct {
	Version   string
	Revision  string
	Modified  bool
	GoVersion string
}

var (
	once   sync.Once
	cached Info
)

func Read() Info {
	once.Do(func() {
		cached = Info{Version: version, Revision: revision, GoVersion: runtime.Version()}
		if cached.Revision == "" {
			cached.Revision = "unknown"
		}
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if revision == "" {
					cached.Revision = setting.Value
				}
			case "vcs.modified":
				cached.Modified = setting.Value == "true"
			}
		}
	})
	return cached
}
