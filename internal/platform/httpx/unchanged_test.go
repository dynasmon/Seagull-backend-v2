package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
)

func TestARequestHoldsARepresentationOnlyByItsTag(t *testing.T) {
	const tag = `"5d41402abc4b2a76b9719d911017c592"`
	for name, tested := range map[string]struct {
		held      []string
		unchanged bool
	}{
		"nothing held":             {held: nil, unchanged: false},
		"the same tag":             {held: []string{tag}, unchanged: true},
		"the same tag weakly":      {held: []string{`W/` + tag}, unchanged: true},
		"among several":            {held: []string{`"a", ` + tag + `, "b"`}, unchanged: true},
		"on a second header line":  {held: []string{`"a"`, tag}, unchanged: true},
		"any representation":       {held: []string{"*"}, unchanged: true},
		"another tag":              {held: []string{`"5d41402abc4b2a76b9719d911017c593"`}, unchanged: false},
		"the tag without quotes":   {held: []string{tag[1 : len(tag)-1]}, unchanged: false},
		"a list naming other tags": {held: []string{`"a", "b"`}, unchanged: false},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/descriptor", nil)
			for _, line := range tested.held {
				r.Header.Add("If-None-Match", line)
			}
			if got := httpx.Unchanged(r, tag); got != tested.unchanged {
				t.Fatalf("a request holding %q was unchanged=%v", tested.held, got)
			}
		})
	}
}
