package main

import (
	"fmt"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "query-api"

type configuration struct {
	service service.Config

	address         string
	certificateFile string
	keyFile         string
	callerCAFile    string

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
	maxBodyBytes int64

	limits    hunt.Limits
	cursorKey config.Secret

	store clickhouse.Config
}

// The ceilings are the ones v1 arrived at operationally — thirty days of
// lookback, five hundred records to a page — kept because they were learned
// rather than because they were inherited.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		address:         parser.String("SEAGULL_QUERY_API_ADDRESS", "127.0.0.1:8444"),
		certificateFile: parser.RequiredFilePath("SEAGULL_QUERY_API_TLS_CERT"),
		keyFile:         parser.RequiredFilePath("SEAGULL_QUERY_API_TLS_KEY"),
		callerCAFile:    parser.RequiredFilePath("SEAGULL_QUERY_API_CALLER_CA"),

		readTimeout:  parser.Duration("SEAGULL_QUERY_API_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		writeTimeout: parser.Duration("SEAGULL_QUERY_API_WRITE_TIMEOUT", 60*time.Second, time.Second, 10*time.Minute),
		idleTimeout:  parser.Duration("SEAGULL_QUERY_API_IDLE_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
		maxBodyBytes: parser.Bytes("SEAGULL_QUERY_API_MAX_BODY", 256<<10, 4<<10, 1<<20),

		limits: hunt.Limits{
			Window:      parser.Duration("SEAGULL_QUERY_API_WINDOW", 720*time.Hour, time.Minute, 8760*time.Hour),
			Page:        parser.Int("SEAGULL_QUERY_API_PAGE", 50, 1, 500),
			MaxPage:     parser.Int("SEAGULL_QUERY_API_PAGE_MAX", 500, 1, 5000),
			Timeout:     parser.Duration("SEAGULL_QUERY_API_READ_BUDGET", 15*time.Second, time.Second, 5*time.Minute),
			MaxRowsRead: uint64(parser.Int("SEAGULL_QUERY_API_MAX_ROWS_READ", 50_000_000, 1_000, 10_000_000_000)),
		},
		cursorKey: parser.Secret("SEAGULL_QUERY_API_CURSOR_KEY"),

		store: storeConfig(parser),
	}

	if err := parser.Err(); err != nil {
		return configuration{}, err
	}
	if err := loaded.coherent(); err != nil {
		return configuration{}, err
	}
	return loaded, nil
}

// A read budget the listener will not wait out is a query that is cut off after
// the store has already paid for it, so the write timeout has to outlast it.
func (c configuration) coherent() error {
	if c.limits.Page > c.limits.MaxPage {
		return fmt.Errorf(
			"invalid configuration: SEAGULL_QUERY_API_PAGE is %d and SEAGULL_QUERY_API_PAGE_MAX is %d",
			c.limits.Page, c.limits.MaxPage)
	}
	if c.writeTimeout <= c.limits.Timeout {
		return fmt.Errorf(
			"invalid configuration: SEAGULL_QUERY_API_WRITE_TIMEOUT %s does not outlast SEAGULL_QUERY_API_READ_BUDGET %s",
			c.writeTimeout, c.limits.Timeout)
	}
	if !c.cursorKey.Empty() && len(c.cursorKey.Reveal()) < 32 {
		return fmt.Errorf("invalid configuration: SEAGULL_QUERY_API_CURSOR_KEY is shorter than 32 bytes")
	}
	return nil
}

// Its own configuration, pointing at the same server as the writers' by default.
// The account it connects with should be able to read and nothing else: this
// process answers questions and never changes the evidence it answers from.
func storeConfig(parser *config.Parser) clickhouse.Config {
	return clickhouse.Config{
		Address:  parser.RequiredString("SEAGULL_QUERY_STORE_ADDRESS"),
		Database: parser.String("SEAGULL_QUERY_STORE_DATABASE", "seagull"),
		User:     parser.String("SEAGULL_QUERY_STORE_USER", "seagull"),
		Password: parser.Secret("SEAGULL_QUERY_STORE_PASSWORD"),
		Timeout:  parser.Duration("SEAGULL_QUERY_STORE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}
}
