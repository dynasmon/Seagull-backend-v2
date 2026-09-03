// Package postgres holds the relational store: the alerts a person owns, their
// trail, and the schema both live in. It is an adapter — an executable chooses
// it, and what an alert means is stated in internal/alert.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const (
	alertsTable              = "alerts"
	transitionsTable         = "alert_transitions"
	incidentsTable           = "incidents"
	incidentTransitionsTable = "incident_transitions"
)

type Config struct {
	Address     string
	Database    string
	User        string
	Password    config.Secret
	SSLMode     string
	MaxConns    int
	Timeout     time.Duration
	ConnTimeout time.Duration
}

func LoadConfig(prefix string, parser *config.Parser) Config {
	return Config{
		Address:     parser.RequiredString(prefix + "_ADDRESS"),
		Database:    parser.String(prefix+"_DATABASE", "seagull"),
		User:        parser.String(prefix+"_USER", "seagull"),
		Password:    parser.Secret(prefix + "_PASSWORD"),
		SSLMode:     parser.String(prefix+"_SSLMODE", "prefer"),
		MaxConns:    parser.Int(prefix+"_MAX_CONNECTIONS", 8, 1, 256),
		Timeout:     parser.Duration(prefix+"_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		ConnTimeout: parser.Duration(prefix+"_CONNECT_TIMEOUT", 10*time.Second, time.Second, time.Minute),
	}
}

func (c Config) Validate() error {
	switch {
	case c.Address == "":
		return errors.New("the alert store needs an address")
	case c.Database == "":
		return errors.New("the alert store needs a database")
	case c.User == "":
		return errors.New("the alert store needs a user")
	}
	return nil
}

// The password reaches the driver through the parsed configuration rather than
// through a string this process formats, so it cannot be carried into a log
// line by a connection string somebody prints.
func (c Config) dsn() string {
	settings := url.Values{}
	settings.Set("sslmode", c.SSLMode)
	settings.Set("connect_timeout", strconv.Itoa(int(c.ConnTimeout.Seconds())))
	settings.Set("application_name", "seagull/"+buildinfo.Read().Version)

	return (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, string(c.Password)),
		Host:     c.Address,
		Path:     "/" + c.Database,
		RawQuery: settings.Encode(),
	}).String()
}

type Store struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func New(ctx context.Context, configuration Config) (*Store, error) {
	pool, err := connect(ctx, configuration)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, timeout: configuration.Timeout}, nil
}

func connect(ctx context.Context, configuration Config) (*pgxpool.Pool, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	settings, err := pgxpool.ParseConfig(configuration.dsn())
	if err != nil {
		return nil, fmt.Errorf("read the alert store address: %w", err)
	}
	settings.MaxConns = int32(configuration.MaxConns)

	pool, err := pgxpool.NewWithConfig(ctx, settings)
	if err != nil {
		return nil, fmt.Errorf("reach the alert store: %w", err)
	}
	return pool, nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("reach the alert store: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Migrations are applied by alert-migrator and never here: a process on its way
// to serving traffic refuses to run against a schema behind the one it ships.
func (s *Store) VerifySchema(ctx context.Context) error {
	for _, table := range []string{alertsTable, transitionsTable, incidentsTable, incidentTransitionsTable} {
		var present bool
		err := s.pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&present)
		if err != nil {
			return fmt.Errorf("read the alert store schema: %w", err)
		}
		if !present {
			return fmt.Errorf("the alert store has no %s table: run alert-migrator", table)
		}
	}
	return nil
}
