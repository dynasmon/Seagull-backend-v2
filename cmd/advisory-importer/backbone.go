package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// The importer reads back what it published before it asks a feed anything. A
// record this build cannot decode is passed over rather than stopping the
// replay: the advisory it held is simply not held, and is asked for again.
type history struct {
	log    *broker.StateLog
	logger *slog.Logger
}

func (h history) Replay(ctx context.Context, learn func(*vulnerabilityv1.Record)) error {
	return h.log.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var decoded vulnerabilityv1.Record
			if err := proto.Unmarshal(record.Value, &decoded); err != nil {
				h.logger.Warn("advisory_record_unreadable", slog.Int64("offset", record.Offset), slog.String("error", err.Error()))
				continue
			}
			learn(&decoded)
		}
		return nil
	})
}

// Only the trust store the operating system has, or the one bundle a mirror is
// signed by: a feed is what decides what the platform calls vulnerable, and
// there is no setting that reads one without checking who is answering.
func client(settings configuration) (*http.Client, error) {
	transport, cloned := http.DefaultTransport.(*http.Transport)
	if !cloned {
		return nil, errors.New("the default http transport is not one this build can configure")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = settings.concurrency

	if settings.authority != "" {
		bundle, err := os.ReadFile(settings.authority)
		if err != nil {
			return nil, fmt.Errorf("read the authority the advisory export is signed by: %w", err)
		}
		authorities := x509.NewCertPool()
		if !authorities.AppendCertsFromPEM(bundle) {
			return nil, fmt.Errorf("%s holds no certificate", settings.authority)
		}
		transport.TLSClientConfig.RootCAs = authorities
	}
	return &http.Client{Timeout: settings.fetchTimeout, Transport: transport}, nil
}
