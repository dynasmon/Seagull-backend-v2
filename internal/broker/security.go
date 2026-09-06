package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const (
	MechanismNone        = "none"
	MechanismScramSHA256 = "scram-sha-256"
	MechanismScramSHA512 = "scram-sha-512"
)

// How a process reaches the backbone. Every client in this package is built
// from it, so encryption and authentication cannot be on for one leg of the
// data plane and off for another.
//
// There is no option to skip verification. A deployment that cannot verify the
// brokers names the authority that signs them.
type Security struct {
	TLS        bool
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string

	Mechanism string
	User      string
	Password  config.Secret
}

func LoadSecurity(parser *config.Parser) Security {
	return Security{
		TLS:        parser.Bool("SEAGULL_BACKBONE_TLS", false),
		CAFile:     parser.FilePath("SEAGULL_BACKBONE_TLS_CA", ""),
		CertFile:   parser.FilePath("SEAGULL_BACKBONE_TLS_CERT", ""),
		KeyFile:    parser.FilePath("SEAGULL_BACKBONE_TLS_KEY", ""),
		ServerName: parser.String("SEAGULL_BACKBONE_TLS_SERVER_NAME", ""),

		Mechanism: parser.Enum("SEAGULL_BACKBONE_SASL_MECHANISM", MechanismNone,
			MechanismNone, MechanismScramSHA256, MechanismScramSHA512),
		User:     parser.String("SEAGULL_BACKBONE_SASL_USER", ""),
		Password: parser.Secret("SEAGULL_BACKBONE_SASL_PASSWORD"),
	}
}

func (s Security) Encrypted() bool { return s.TLS }

func (s Security) Authenticated() bool { return s.Mechanism != "" && s.Mechanism != MechanismNone }

func (s Security) Validate() error {
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("a backbone client certificate needs its key, and a key needs its certificate")
	}
	if !s.TLS && (s.CAFile != "" || s.CertFile != "") {
		return errors.New("backbone tls material was given and tls is off")
	}
	if s.Authenticated() && (s.User == "" || s.Password.Reveal() == "") {
		return fmt.Errorf("%s needs a user and a password", s.Mechanism)
	}
	if !s.Authenticated() && s.User != "" {
		return errors.New("a backbone user was given and no mechanism to authenticate it with")
	}
	// Credentials on a plaintext connection are read by anything on the path.
	if s.Authenticated() && !s.TLS {
		return errors.New("backbone authentication without tls would send the password in the clear")
	}
	return nil
}

func (s Security) options() ([]kgo.Opt, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	var options []kgo.Opt
	if s.TLS {
		configured, err := s.tls()
		if err != nil {
			return nil, err
		}
		options = append(options, kgo.DialTLSConfig(configured))
	}

	switch s.Mechanism {
	case MechanismScramSHA256:
		options = append(options, kgo.SASL(scram.Auth{User: s.User, Pass: s.Password.Reveal()}.AsSha256Mechanism()))
	case MechanismScramSHA512:
		options = append(options, kgo.SASL(scram.Auth{User: s.User, Pass: s.Password.Reveal()}.AsSha512Mechanism()))
	}
	return options, nil
}

func (s Security) tls() (*tls.Config, error) {
	configured := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.ServerName}

	if s.CAFile != "" {
		authority, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read the backbone authority: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(authority) {
			return nil, fmt.Errorf("%s carries no certificate", s.CAFile)
		}
		configured.RootCAs = pool
	}

	if s.CertFile != "" {
		identity, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read the backbone client identity: %w", err)
		}
		configured.Certificates = []tls.Certificate{identity}
	}
	return configured, nil
}
