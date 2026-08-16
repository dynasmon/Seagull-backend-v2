package main

import (
	"fmt"
	"net"
	"time"

	"github.com/dynasmon/Seagull-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-v2/internal/platform/service"
)

const serviceName = "control-api"

type configuration struct {
	service service.Config

	address         string
	certificateFile string
	keyFile         string

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
	maxBodyBytes int64
}

func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		address:         parser.String("SEAGULL_CONTROL_API_ADDRESS", "127.0.0.1:8080"),
		certificateFile: parser.FilePath("SEAGULL_CONTROL_API_TLS_CERT", ""),
		keyFile:         parser.FilePath("SEAGULL_CONTROL_API_TLS_KEY", ""),

		readTimeout:  parser.Duration("SEAGULL_CONTROL_API_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		writeTimeout: parser.Duration("SEAGULL_CONTROL_API_WRITE_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		idleTimeout:  parser.Duration("SEAGULL_CONTROL_API_IDLE_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
		maxBodyBytes: parser.Bytes("SEAGULL_CONTROL_API_MAX_BODY", 1<<20, 4<<10, 8<<20),
	}

	if err := parser.Err(); err != nil {
		return configuration{}, err
	}
	if err := loaded.refuseExposedPlaintext(); err != nil {
		return configuration{}, err
	}
	return loaded, nil
}

// Serving the control API in the clear is a local development convenience. A
// listener reachable beyond loopback has to carry TLS or the process refuses to
// start, so an exposed deployment cannot happen by leaving a variable unset.
func (c configuration) refuseExposedPlaintext() error {
	if c.certificateFile != "" && c.keyFile != "" {
		return nil
	}
	if c.certificateFile != "" || c.keyFile != "" {
		return fmt.Errorf(
			"invalid configuration: SEAGULL_CONTROL_API_TLS_CERT and SEAGULL_CONTROL_API_TLS_KEY are set together or not at all",
		)
	}
	if loopbackOnly(c.address) {
		return nil
	}
	return fmt.Errorf(
		"invalid configuration: SEAGULL_CONTROL_API_ADDRESS %q reaches beyond loopback and no TLS material is configured",
		c.address,
	)
}

func loopbackOnly(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}
