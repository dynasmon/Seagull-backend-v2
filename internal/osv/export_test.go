package osv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisoryfeed"
)

const index = `2026-09-13T16:00:09.623179803Z,DEBIAN-CVE-2026-73282
2026-09-12T11:00:05.986201214Z,DEBIAN-CVE-2024-58382

2026-03-31T22:31:29.677499Z,DSA-6189-1
not a time,DSA-1
2026-03-31T22:31:29Z,DSA 1
2026-03-31T22:31:29Z
`

func TestAnIndexListsEveryRecordItNamesAndCountsTheLinesItCannotRead(t *testing.T) {
	listings, malformed := ParseIndex([]byte(index))
	if malformed != 3 {
		t.Errorf("%d lines were counted as unreadable, want 3", malformed)
	}
	want := []advisoryfeed.Listing{
		{ID: "DEBIAN-CVE-2026-73282", Modified: time.Date(2026, time.September, 13, 16, 0, 9, 623179803, time.UTC)},
		{ID: "DEBIAN-CVE-2024-58382", Modified: time.Date(2026, time.September, 12, 11, 0, 5, 986201214, time.UTC)},
		{ID: "DSA-6189-1", Modified: time.Date(2026, time.March, 31, 22, 31, 29, 677499000, time.UTC)},
	}
	if len(listings) != len(want) {
		t.Fatalf("listed %v, want %v", listings, want)
	}
	for position := range want {
		if listings[position].ID != want[position].ID || !listings[position].Modified.Equal(want[position].Modified) {
			t.Errorf("listing %d is %+v, want %+v", position, listings[position], want[position])
		}
	}
}

type mirror struct {
	server   *httptest.Server
	requests atomic.Int32
	paths    chan string
}

func serving(t *testing.T, handler http.HandlerFunc) (*mirror, *Export) {
	t.Helper()
	served := &mirror{paths: make(chan string, 64)}
	served.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		served.requests.Add(1)
		select {
		case served.paths <- request.URL.Path:
		default:
		}
		handler(writer, request)
	}))
	t.Cleanup(served.server.Close)

	export, err := NewExport(ExportOptions{
		Base:           served.server.URL,
		Client:         served.server.Client(),
		MaxIndexBytes:  4 << 10,
		MaxRecordBytes: 4 << 10,
		UserAgent:      "seagull-test",
	})
	if err != nil {
		t.Fatalf("build the export: %v", err)
	}
	return served, export
}

func TestAnIndexIsVersionedByWhatTheOriginSaysItIs(t *testing.T) {
	served, export := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("If-None-Match") == `"generation-2"` {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", `"generation-2"`)
		_, _ = writer.Write([]byte(index))
	})

	read, err := export.Index(context.Background(), "Rocky Linux", "")
	if err != nil {
		t.Fatalf("read the index: %v", err)
	}
	if read.Version != `"generation-2"` || read.Unchanged || len(read.Listings) != 3 || read.Malformed != 3 {
		t.Errorf("read %+v", read)
	}
	if path := <-served.paths; path != "/Rocky Linux/modified_id.csv" {
		t.Errorf("the index was asked for at %q", path)
	}

	again, err := export.Index(context.Background(), "Rocky Linux", read.Version)
	if err != nil {
		t.Fatalf("read the index again: %v", err)
	}
	if !again.Unchanged || again.Version != read.Version || len(again.Listings) != 0 {
		t.Errorf("an index the origin says has not changed was read as %+v", again)
	}
}

func TestAnIndexWithoutAValidatorIsVersionedByItsContent(t *testing.T) {
	_, export := serving(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte(index)) })

	read, err := export.Index(context.Background(), "Debian", "")
	if err != nil {
		t.Fatalf("read the index: %v", err)
	}
	if want := "sha256:"; !strings.HasPrefix(read.Version, want) || len(read.Version) != len(want)+64 {
		t.Errorf("an index with no ETag is versioned %q", read.Version)
	}

	again, err := export.Index(context.Background(), "Debian", read.Version)
	if err != nil {
		t.Fatalf("read the index again: %v", err)
	}
	if !again.Unchanged {
		t.Errorf("an index whose content did not change was read as %+v", again)
	}
}

func TestAnOriginThatIsDownIsWorthAskingAgainAndOneThatAnsweredIsNot(t *testing.T) {
	for _, case_ := range []struct {
		name      string
		status    int
		transient bool
	}{
		{"busy", http.StatusTooManyRequests, true},
		{"failing", http.StatusBadGateway, true},
		{"unavailable", http.StatusServiceUnavailable, true},
		{"missing", http.StatusNotFound, false},
		{"forbidden", http.StatusForbidden, false},
	} {
		_, export := serving(t, func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(case_.status) })

		_, err := export.Index(context.Background(), "Debian", "")
		var unavailable *advisoryfeed.Unavailable
		if err == nil || errors.As(err, &unavailable) != case_.transient {
			t.Errorf("%s index: %v, want transient %v", case_.name, err, case_.transient)
		}
	}
}

func TestARecordTheIndexListedAndTheOriginNoLongerHasIsGone(t *testing.T) {
	served, export := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/Rocky Linux/RLSA-2026:66203.json":
			_, _ = writer.Write([]byte(rockyRecord))
		case "/Rocky Linux/RLSA-2026:1.json":
			writer.WriteHeader(http.StatusInternalServerError)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})

	fetched, err := export.Record(context.Background(), "Rocky Linux", "RLSA-2026:66203")
	if err != nil {
		t.Fatalf("fetch the record: %v", err)
	}
	if string(fetched.Body) != rockyRecord || fetched.Location != served.server.URL+"/Rocky%20Linux/RLSA-2026:66203.json" {
		t.Errorf("fetched %d bytes from %q", len(fetched.Body), fetched.Location)
	}

	if _, err := export.Record(context.Background(), "Rocky Linux", "RLSA-2026:0"); !errors.Is(err, advisoryfeed.ErrGone) {
		t.Errorf("a record the origin does not have: %v", err)
	}
	var unavailable *advisoryfeed.Unavailable
	if _, err := export.Record(context.Background(), "Rocky Linux", "RLSA-2026:1"); !errors.As(err, &unavailable) {
		t.Errorf("a record the origin failed to serve: %v", err)
	}
}

func TestWhatIsLargerThanItsCeilingIsNotReadWhole(t *testing.T) {
	_, export := serving(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 5<<10)))
	})

	var unavailable *advisoryfeed.Unavailable
	if _, err := export.Index(context.Background(), "Debian", ""); err == nil || errors.As(err, &unavailable) {
		t.Errorf("an oversized index: %v", err)
	}
	if _, err := export.Record(context.Background(), "Debian", "DSA-6189-1"); err == nil || errors.As(err, &unavailable) || errors.Is(err, advisoryfeed.ErrGone) {
		t.Errorf("an oversized record: %v", err)
	}
}

func TestAnExportIsOnlyEverReadOverTLS(t *testing.T) {
	if _, err := NewExport(ExportOptions{Base: "http://osv.example", Client: http.DefaultClient, MaxIndexBytes: 1, MaxRecordBytes: 1}); err == nil {
		t.Error("an export over plaintext was accepted")
	}

	plain := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte(index)) }))
	t.Cleanup(plain.Close)
	_, export := serving(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, plain.URL+request.URL.Path, http.StatusFound)
	})
	if _, err := export.Index(context.Background(), "Debian", ""); err == nil {
		t.Error("a redirect to plaintext was followed")
	}
}
