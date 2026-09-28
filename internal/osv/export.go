package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisoryfeed"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
)

const indexName = "modified_id.csv"

var errUntrustedRedirect = errors.New("the export redirected to an untrusted origin")

type ExportOptions struct {
	Base           string
	Client         *http.Client
	MaxIndexBytes  int64
	MaxRecordBytes int64
	UserAgent      string
}

// OSV's public export, or a mirror laid out the same way: per feed, an index
// of every record and when it last changed, and each record on its own.
type Export struct {
	base           string
	client         *http.Client
	maxIndexBytes  int64
	maxRecordBytes int64
	userAgent      string
}

// Only https, redirects included: what a feed says decides what the platform
// calls vulnerable, and a feed read in the clear is one anybody on the path can
// edit into saying a package is fixed.
func NewExport(options ExportOptions) (*Export, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(options.Base), "/"))
	switch {
	case err != nil:
		return nil, fmt.Errorf("the advisory export %q is not a URL: %w", options.Base, err)
	case base.Scheme != "https" || base.Host == "":
		return nil, fmt.Errorf("the advisory export %q is not read over https", options.Base)
	case base.RawQuery != "" || base.Fragment != "" || base.User != nil:
		return nil, fmt.Errorf("the advisory export %q carries more than a location", base.Redacted())
	case options.Client == nil:
		return nil, errors.New("the advisory export needs an http client")
	case options.MaxIndexBytes <= 0 || options.MaxRecordBytes <= 0:
		return nil, errors.New("the advisory export needs a ceiling on what it reads")
	}

	client := *options.Client
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != base.Scheme || !strings.EqualFold(request.URL.Host, base.Host) || request.URL.User != nil {
			return fmt.Errorf("%w: %s", errUntrustedRedirect, request.URL.Redacted())
		}
		if len(via) >= 5 {
			return errors.New("the export redirected more than five times")
		}
		if checkRedirect != nil {
			return checkRedirect(request, via)
		}
		return nil
	}

	agent := options.UserAgent
	if agent == "" {
		agent = "seagull-advisory-importer"
	}
	return &Export{
		base:           base.String(),
		client:         &client,
		maxIndexBytes:  options.MaxIndexBytes,
		maxRecordBytes: options.MaxRecordBytes,
		userAgent:      agent,
	}, nil
}

func (e *Export) Index(ctx context.Context, feed, known string) (advisoryfeed.Index, error) {
	location := e.locate(feed, indexName)
	response, err := e.get(ctx, location, known)
	if err != nil {
		return advisoryfeed.Index{}, err
	}
	defer drain(response)

	switch {
	case response.StatusCode == http.StatusNotModified && known != "":
		return advisoryfeed.Index{Version: known, Unchanged: true}, nil
	case response.StatusCode != http.StatusOK:
		return advisoryfeed.Index{}, refusal(location, response.StatusCode)
	}

	body, err := bounded(response.Body, e.maxIndexBytes, location)
	if err != nil {
		return advisoryfeed.Index{}, err
	}
	version := strings.TrimSpace(response.Header.Get("ETag"))
	if version == "" {
		digest := sha256.Sum256(body)
		version = "sha256:" + hex.EncodeToString(digest[:])
	}
	if version == known {
		return advisoryfeed.Index{Version: known, Unchanged: true}, nil
	}

	listings, malformed := ParseIndex(body)
	return advisoryfeed.Index{Listings: listings, Version: version, Malformed: malformed}, nil
}

func (e *Export) Record(ctx context.Context, feed, id string) (advisoryfeed.Fetched, error) {
	location := e.locate(feed, id+".json")
	response, err := e.get(ctx, location, "")
	if err != nil {
		return advisoryfeed.Fetched{}, err
	}
	defer drain(response)

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return advisoryfeed.Fetched{}, fmt.Errorf("%s: %w", location, advisoryfeed.ErrGone)
	default:
		return advisoryfeed.Fetched{}, refusal(location, response.StatusCode)
	}

	body, err := bounded(response.Body, e.maxRecordBytes, location)
	if err != nil {
		return advisoryfeed.Fetched{}, err
	}
	return advisoryfeed.Fetched{Body: body, Location: location}, nil
}

func ParseIndex(body []byte) ([]advisoryfeed.Listing, int) {
	var (
		listings  []advisoryfeed.Listing
		malformed int
	)
	for _, line := range bytes.Split(body, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}
		spelled, id, found := strings.Cut(trimmed, ",")
		modified, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(spelled))
		id = strings.TrimSpace(id)
		if !found || err != nil || !vulnerability.Identifier(id) {
			malformed++
			continue
		}
		listings = append(listings, advisoryfeed.Listing{ID: id, Modified: modified.UTC()})
	}
	return listings, malformed
}

func (e *Export) locate(feed, name string) string {
	return e.base + "/" + url.PathEscape(feed) + "/" + url.PathEscape(name)
}

func (e *Export) get(ctx context.Context, location, known string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, fmt.Errorf("ask %s: %w", location, err)
	}
	request.Header.Set("User-Agent", e.userAgent)
	if known != "" {
		request.Header.Set("If-None-Match", known)
	}

	response, err := e.client.Do(request)
	switch {
	case err == nil:
		return response, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(err, errUntrustedRedirect):
		return nil, err
	default:
		return nil, &advisoryfeed.Unavailable{Err: err}
	}
}

func refusal(location string, status int) error {
	failure := fmt.Errorf("%s answered %d", location, status)
	if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return &advisoryfeed.Unavailable{Err: failure}
	}
	return failure
}

func bounded(body io.Reader, limit int64, location string) ([]byte, error) {
	read, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, &advisoryfeed.Unavailable{Err: fmt.Errorf("read %s: %w", location, err)}
	}
	if int64(len(read)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d bytes the platform reads", location, limit)
	}
	return read, nil
}

func drain(response *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
}
