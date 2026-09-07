package agent

import (
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	MaxSubjectLength  = 256
	MaxSerialLength   = 64
	FingerprintLength = 64
)

var ErrMalformedIdentity = errors.New("the certificate identity cannot be bound to this agent")

// The subject a binding carries is the certificate's common name, which is what
// the gateway reads a connection's identity from, so a certificate naming
// somebody else is refused here rather than recorded and never matched.
func Bindable(agentID string, held *agentv1.Identity, at time.Time) error {
	if held == nil {
		return fmt.Errorf("%w: no certificate identity was given", ErrMalformedIdentity)
	}
	if held.GetSubject() != agentID {
		return fmt.Errorf("%w: it names %q and this agent is %q", ErrMalformedIdentity, held.GetSubject(), agentID)
	}
	if len(held.GetSubject()) > MaxSubjectLength {
		return fmt.Errorf("%w: the subject is longer than %d bytes", ErrMalformedIdentity, MaxSubjectLength)
	}
	if err := serial(held.GetSerial()); err != nil {
		return err
	}
	if err := fingerprint(held.GetFingerprintSha256()); err != nil {
		return err
	}
	return validity(held, at)
}

func serial(value string) error {
	if value == "" {
		return fmt.Errorf("%w: it carries no serial", ErrMalformedIdentity)
	}
	if len(value) > MaxSerialLength {
		return fmt.Errorf("%w: the serial is longer than %d bytes", ErrMalformedIdentity, MaxSerialLength)
	}
	if !hexadecimal(value) {
		return fmt.Errorf("%w: the serial %q is not hexadecimal", ErrMalformedIdentity, value)
	}
	return nil
}

func fingerprint(value string) error {
	if len(value) != FingerprintLength || !hexadecimal(value) {
		return fmt.Errorf("%w: the fingerprint is not %d hexadecimal characters of SHA-256",
			ErrMalformedIdentity, FingerprintLength)
	}
	if strings.ToLower(value) != value {
		return fmt.Errorf("%w: the fingerprint is written in lower case", ErrMalformedIdentity)
	}
	return nil
}

func validity(held *agentv1.Identity, at time.Time) error {
	issued, expires := held.GetIssuedAt(), held.GetExpiresAt()
	if !expires.IsValid() || expires.AsTime().IsZero() {
		return fmt.Errorf("%w: it says when it expires or it is not bound", ErrMalformedIdentity)
	}
	if issued.IsValid() && !issued.AsTime().IsZero() && !expires.AsTime().After(issued.AsTime()) {
		return fmt.Errorf("%w: it expires at or before it was issued", ErrMalformedIdentity)
	}
	if !expires.AsTime().After(at) {
		return fmt.Errorf("%w: it expired at %s", ErrMalformedIdentity, expires.AsTime().UTC().Format(time.RFC3339))
	}
	return nil
}

func hexadecimal(value string) bool {
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		case character >= 'A' && character <= 'F':
		default:
			return false
		}
	}
	return value != ""
}
