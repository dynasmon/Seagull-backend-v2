package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const table = "security_events"

// One decision written twice, in the same order. NewStore refuses to build a
// store whose columns are not the ones the embedded schema creates.
var storedColumns = []string{
	"event_id",
	"schema_version",
	"event_class",
	"event_time",
	"observed_time",
	"ingest_time",

	"tenant_id",
	"agent_id",
	"host_hostname",
	"host_ip",
	"host_os",
	"host_architecture",

	"collector",
	"source",
	"sequence",

	"gateway",
	"batch_id",

	"auth_activity",
	"auth_outcome",
	"auth_outcome_reason",
	"auth_method",
	"auth_user_name",
	"auth_user_domain",
	"auth_user_uid",
	"auth_service_name",
	"auth_service_protocol",
	"auth_source_ip",
	"auth_source_port",
	"auth_destination_ip",
	"auth_destination_port",
	"auth_transport",
	"auth_raw_record",
}

func values(row eventstore.Row) []any {
	return []any{
		row.EventID,
		row.SchemaVersion,
		row.EventClass,
		row.EventTime,
		row.ObservedTime,
		row.IngestTime,

		row.TenantID,
		row.AgentID,
		row.HostHostname,
		row.HostIP,
		row.HostOS,
		row.HostArchitecture,

		row.Collector,
		row.Source,
		row.Sequence,

		row.Gateway,
		row.BatchID,

		row.AuthActivity,
		row.AuthOutcome,
		row.AuthOutcomeReason,
		row.AuthMethod,
		row.AuthUserName,
		row.AuthUserDomain,
		row.AuthUserUID,
		row.AuthServiceName,
		row.AuthServiceProtocol,
		row.AuthSourceIP,
		row.AuthSourcePort,
		row.AuthDestinationIP,
		row.AuthDestinationPort,
		row.AuthTransport,
		row.AuthRawRecord,
	}
}

type Config struct {
	Address  string
	Database string
	User     string
	Password config.Secret
	Timeout  time.Duration
}

type Store struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewStore(configuration Config) (*Store, error) {
	if err := agreesWithSchema(); err != nil {
		return nil, err
	}

	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}

	return &Store{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", table, strings.Join(storedColumns, ", ")),
	}, nil
}

func (s *Store) Store(ctx context.Context, rows []eventstore.Row) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", table, err)
	}
	for _, row := range rows {
		if err := batch.Append(values(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add event %s to the batch: %w", row.EventID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d events to %s: %w", len(rows), table, err)
	}
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the event store: %w", err)
	}
	return nil
}

// Fail closed: a writer whose store is behind the schema it ships refuses to
// start rather than writing into a table that cannot hold the rows.
func (s *Store) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the event store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return s.verifyColumns(ctx)
}

// NewStore checks the embedded DDL; this asks the running database, which is
// what also covers a column added by a later ALTER.
func (s *Store) verifyColumns(ctx context.Context) error {
	rows, err := s.connection.Query(ctx,
		"SELECT name FROM system.columns WHERE database = ? AND table = ?", s.database, table)
	if err != nil {
		return fmt.Errorf("read the columns of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	present := map[string]struct{}{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("read the columns of %s: %w", table, err)
		}
		present[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read the columns of %s: %w", table, err)
	}

	var missing []string
	for _, column := range storedColumns {
		if _, ok := present[column]; !ok {
			missing = append(missing, column)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s.%s does not hold %s", s.database, table, strings.Join(missing, ", "))
	}
	return nil
}

func (s *Store) Close() error { return s.connection.Close() }

func agreesWithSchema() error {
	declared, err := declaredColumns(table)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, storedColumns) {
		return fmt.Errorf("the store writes %d columns and the schema creates %d: %s versus %s",
			len(storedColumns), len(declared),
			strings.Join(storedColumns, ", "), strings.Join(declared, ", "))
	}
	if length := len(values(eventstore.Row{})); length != len(storedColumns) {
		return fmt.Errorf("the store names %d columns and supplies %d values", len(storedColumns), length)
	}
	return nil
}

// No TLS, deliberately: the gateway already reaches Redpanda in the clear on the
// same internal network, and securing one leg and not the other proves nothing.
func connect(configuration Config) (driver.Conn, error) {
	switch {
	case configuration.Address == "":
		return nil, errors.New("the event store needs an address")
	case configuration.Database == "":
		return nil, errors.New("the event store needs a database")
	case configuration.Timeout <= 0:
		return nil, errors.New("the event store needs a positive timeout")
	}

	connection, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{configuration.Address},
		Auth: clickhouse.Auth{
			Database: configuration.Database,
			Username: configuration.User,
			Password: configuration.Password.Reveal(),
		},
		ClientInfo: clickhouse.ClientInfo{
			Products: []struct {
				Name    string
				Version string
			}{{Name: "seagull", Version: buildinfo.Read().Version}},
		},
		Compression:  &clickhouse.Compression{Method: clickhouse.CompressionZSTD},
		DialTimeout:  configuration.Timeout,
		MaxOpenConns: 2,
		MaxIdleConns: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("create the event store client: %w", err)
	}
	return connection, nil
}
