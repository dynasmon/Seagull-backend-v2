package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	platformmetrics "github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func TestARefusalIsNamedByWhatTheBackboneRefused(t *testing.T) {
	for _, case_ := range []struct {
		err  error
		want error
	}{
		{fmt.Errorf("dial: %w", kerr.SaslAuthenticationFailed), ErrNotAuthenticated},
		{kerr.UnsupportedSaslMechanism, ErrNotAuthenticated},
		{kerr.TopicAuthorizationFailed, ErrNotAuthorized},
		{kerr.GroupAuthorizationFailed, ErrNotAuthorized},
		{kerr.ClusterAuthorizationFailed, ErrNotAuthorized},
	} {
		got := named(case_.err)
		if !errors.Is(got, case_.want) || !errors.Is(got, case_.err) {
			t.Errorf("%v was named %v", case_.err, got)
		}
	}
	other := kerr.NotLeaderForPartition
	if got := named(other); got != other {
		t.Errorf("%v, which refuses nothing, was named %v", other, got)
	}
}

func TestEveryRefusalIsCountedByWhyAndReadinessFailsUntilALookFindsNoNewOne(t *testing.T) {
	registry := platformmetrics.New("denials-test")
	denials := NewDenials(registry)

	if err := denials.Check(context.Background()); err != nil {
		t.Fatalf("a process nothing was refused was not ready: %v", err)
	}
	denials.OnBrokerConnect(kgo.BrokerMetadata{}, 0, nil, kerr.SaslAuthenticationFailed)
	denials.OnGroupManageError(kerr.GroupAuthorizationFailed)
	denials.OnProduceRecordUnbuffered(nil, kerr.TopicAuthorizationFailed)
	denials.OnProduceRecordUnbuffered(nil, nil)
	denials.OnBrokerConnect(kgo.BrokerMetadata{}, 0, nil, errors.New("connection refused"))

	if got := metricValue(t, registry, `seagull_backbone_denials_total{reason="authentication"}`); got != 1 {
		t.Errorf("%v refusals of who the process is were counted", got)
	}
	if got := metricValue(t, registry, `seagull_backbone_denials_total{reason="authorization"}`); got != 2 {
		t.Errorf("%v refusals of what it asked were counted", got)
	}
	err := denials.Check(context.Background())
	if !errors.Is(err, ErrNotAuthorized) || !strings.Contains(err.Error(), "TOPIC_AUTHORIZATION_FAILED") {
		t.Errorf("readiness named %v, want the newest refusal", err)
	}
	if err := denials.Check(context.Background()); err != nil {
		t.Errorf("a look that found no new refusal still failed: %v", err)
	}
	denials.OnBrokerConnect(kgo.BrokerMetadata{}, 0, nil, kerr.SaslAuthenticationFailed)
	if err := denials.Check(context.Background()); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("a refusal after a clean look was named %v", err)
	}
}

func TestAClientWithNoObserverIgnoresWhatItWasRefused(t *testing.T) {
	var unobserved *Denials
	unobserved.observe(kerr.TopicAuthorizationFailed)
}
