package httpx

import (
	"net/http"
	"strings"
)

// Unchanged reports whether a request already holds the representation an
// entity tag names, by the weak comparison RFC 9110 gives If-None-Match: `*`,
// or the tag among those the header lists, a `W/` prefix ignored on either side.
func Unchanged(r *http.Request, tag string) bool {
	wanted := strings.TrimPrefix(tag, "W/")
	for _, line := range r.Header.Values("If-None-Match") {
		for _, held := range strings.Split(line, ",") {
			held = strings.TrimSpace(held)
			if held == "*" || strings.TrimPrefix(held, "W/") == wanted {
				return true
			}
		}
	}
	return false
}
