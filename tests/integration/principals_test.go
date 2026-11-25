//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	platformmetrics "github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const securedAdministrator = "backbone-migrator"

type securedBackbone struct {
	addresses     []string
	authority     string
	administrator broker.Security
}

func secured(t *testing.T) securedBackbone {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("SEAGULL_TEST_SECURED_BROKERS"))
	if value == "" {
		t.Skip("set SEAGULL_TEST_SECURED_BROKERS to run the suite against a backbone that authenticates and authorizes")
	}
	authority := os.Getenv("SEAGULL_TEST_SECURED_AUTHORITY")
	password, err := os.ReadFile(os.Getenv("SEAGULL_TEST_SECURED_PASSWORD_FILE"))
	if err != nil {
		t.Fatalf("read the password of the secured backbone's administrator: %v", err)
	}
	return securedBackbone{
		addresses: strings.Split(value, ","),
		authority: authority,
		administrator: broker.Security{
			TLS:       true,
			CAFile:    authority,
			Mechanism: broker.MechanismScramSHA256,
			User:      securedAdministrator,
			Password:  config.Secret(strings.TrimSpace(string(password))),
		},
	}
}

func (b securedBackbone) as(component broker.Component, password config.Secret) broker.Security {
	security := b.administrator
	security.User = string(component)
	security.Password = password
	return security
}

func (b securedBackbone) client(t *testing.T, user string, password config.Secret, options ...kgo.Opt) *kgo.Client {
	t.Helper()
	authority, err := os.ReadFile(b.authority)
	if err != nil {
		t.Fatalf("read the secured backbone's authority: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority) {
		t.Fatal("the secured backbone's authority carries no certificate")
	}
	client, err := kgo.NewClient(append([]kgo.Opt{
		kgo.SeedBrokers(b.addresses...),
		kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}),
		kgo.SASL(scram.Auth{User: user, Pass: password.Reveal()}.AsSha256Mechanism()),
		kgo.RequestRetries(2),
		kgo.RetryTimeout(5 * time.Second),
	}, options...)...)
	if err != nil {
		t.Fatalf("connect to the secured backbone as %s: %v", user, err)
	}
	t.Cleanup(client.Close)
	return client
}

// Every topic of the platform, renamed for this run so it shares nothing with
// another run against the same broker.
func securedTopology(t *testing.T) broker.Topology {
	t.Helper()
	parser := config.New(func(key string) (string, bool) {
		value, given := map[string]string{
			"SEAGULL_BACKBONE_DURABILITY":          "development",
			"SEAGULL_BACKBONE_REPLICAS":            "1",
			"SEAGULL_BACKBONE_MIN_INSYNC_REPLICAS": "1",
		}[key]
		return value, given
	})
	topology := broker.LoadTopology(parser)
	if err := parser.Err(); err != nil {
		t.Fatalf("load the topology: %v", err)
	}
	run := fmt.Sprintf("acl.%d.", time.Now().UnixNano())
	fields := reflect.ValueOf(&topology).Elem()
	for i := range fields.NumField() {
		if topic, ok := fields.Field(i).Addr().Interface().(*broker.Topic); ok {
			topic.Name = run + topic.Name
			topic.Partitions = 1
		}
	}
	return topology
}

func passwordsFor(t *testing.T, grants []broker.Grant) map[broker.Component]config.Secret {
	t.Helper()
	passwords := make(map[broker.Component]config.Secret, len(grants))
	for _, grant := range grants {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			t.Fatal(err)
		}
		passwords[grant.Component] = config.Secret(hex.EncodeToString(random))
	}
	return passwords
}

func grantedOn(t *testing.T, backbone securedBackbone, topology broker.Topology) (*broker.Provisioner, []broker.Grant, map[broker.Component]config.Secret) {
	t.Helper()
	provisioner, err := broker.NewProvisioner(backbone.addresses, "integration-test", backbone.administrator)
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	t.Cleanup(provisioner.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		names := make([]string, 0, len(topology.Topics()))
		for _, topic := range topology.Topics() {
			names = append(names, topic.Name)
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = kadm.NewClient(backbone.client(t, securedAdministrator, backbone.administrator.Password)).DeleteTopics(cleanup, names...)
	})
	if _, err := provisioner.Apply(ctx, topology.Topics()); err != nil {
		t.Fatalf("apply the topology: %v", err)
	}
	grants := topology.Grants()
	passwords := passwordsFor(t, grants)
	if _, err := provisioner.ApplyGrants(ctx, grants, passwords); err != nil {
		t.Fatalf("apply the grants: %v", err)
	}
	return provisioner, grants, passwords
}

func firstRefusal(created kadm.CreateACLsResults, err error) error {
	if err != nil {
		return err
	}
	for _, result := range created {
		if result.Err != nil {
			return result.Err
		}
	}
	return nil
}

func written(grant broker.Grant, topic broker.Topic) bool {
	return slices.ContainsFunc(grant.Writes, func(held broker.Topic) bool { return held.Name == topic.Name })
}

func TestEveryComponentWritesWhereItIsGrantedAndIsRefusedEverywhereElse(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	_, grants, passwords := grantedOn(t, backbone, topology)

	for _, grant := range grants {
		client := backbone.client(t, string(grant.Component), passwords[grant.Component], kgo.RequiredAcks(kgo.AllISRAcks()))
		for _, topic := range topology.Topics() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := client.ProduceSync(ctx, &kgo.Record{Topic: topic.Name, Key: []byte("agent"), Value: []byte("probe")}).FirstErr()
			cancel()
			switch {
			case written(grant, topic) && err != nil:
				t.Errorf("%s could not write %s, which it is granted: %v", grant.Component, topic.Name, err)
			case !written(grant, topic) && !errors.Is(err, kerr.TopicAuthorizationFailed) && !(len(grant.Writes) == 0 && errors.Is(err, kerr.ClusterAuthorizationFailed)):
				t.Errorf("%s writing %s, which it is not granted, was answered %v", grant.Component, topic.Name, err)
			}
		}
	}
}

func TestEveryComponentConsumesInItsOwnGroupAndInNoOtherComponentsGroup(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	_, grants, passwords := grantedOn(t, backbone, topology)

	for _, grant := range grants {
		if len(grant.Consumes) == 0 {
			continue
		}
		topics := make([]string, 0, len(grant.Consumes))
		for _, topic := range grant.Consumes {
			topics = append(topics, topic.Name)
		}
		for _, group := range []string{grant.Component.Group(), broker.IngestGateway.Group()} {
			consumer := backbone.client(t, string(grant.Component), passwords[grant.Component],
				kgo.ConsumerGroup(group), kgo.ConsumeTopics(topics...), kgo.DisableAutoCommit())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var refused error
			consumer.PollFetches(ctx).EachError(func(_ string, _ int32, err error) {
				if !errors.Is(err, context.DeadlineExceeded) && refused == nil {
					refused = err
				}
			})
			cancel()
			own := group == grant.Component.Group()
			switch {
			case own && refused != nil:
				t.Errorf("%s was refused consuming in its own group: %v", grant.Component, refused)
			case !own && !errors.Is(refused, kerr.GroupAuthorizationFailed):
				t.Errorf("%s consuming in %s's group was answered %v", grant.Component, group, refused)
			}
			consumer.Close()
		}
	}
}

func TestTheMigratorTakesBackWhatAComponentHoldsBeyondItsGrantAndLeavesOtherPrincipalsAlone(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	provisioner, grants, passwords := grantedOn(t, backbone, topology)
	admin := kadm.NewClient(backbone.client(t, securedAdministrator, backbone.administrator.Password))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	operator := "User:operator-" + strings.TrimSuffix(topology.Events.Name, ".security.events.raw")
	added, err := admin.CreateACLs(ctx, kadm.NewACLs().
		Allow(broker.AlertWriter.Principal(), operator).AllowHosts("*").
		Topics(topology.Agents.Name).Operations(kadm.OpWrite))
	if err := firstRefusal(added, err); err != nil {
		t.Fatalf("add a write beyond the alert writer's grant: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteACLs(cleanup, kadm.NewACLs().Allow(operator).AllowHosts("*").Topics(topology.Agents.Name).Operations(kadm.OpWrite))
	})

	changed, err := provisioner.ApplyGrants(ctx, grants, passwords)
	if err != nil {
		t.Fatalf("apply the grants again: %v", err)
	}
	revoked := "revoked " + broker.AlertWriter.Principal() + " ALLOW WRITE on TOPIC " + topology.Agents.Name
	if !slices.Contains(changed, revoked) {
		t.Errorf("the second run changed %v and did not take back the alert writer's write", changed)
	}
	for _, change := range changed {
		if strings.HasPrefix(change, "granted ") || (strings.HasPrefix(change, "revoked ") && change != revoked) {
			t.Errorf("a second run over an unchanged grant changed %q", change)
		}
	}
	described, err := admin.DescribeACLs(ctx, kadm.NewACLs().Allow(operator).AllowHosts("*").Topics(topology.Agents.Name).Operations(kadm.OpWrite))
	if err != nil || len(described) != 1 || len(described[0].Described) != 1 {
		t.Errorf("the operator's own permission did not survive the migrator: %v %v", described, err)
	}
}

func TestAnACLThatGrantsEveryoneIsRefusedAsABackboneThatEnforcesNone(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	provisioner, grants, passwords := grantedOn(t, backbone, topology)
	admin := kadm.NewClient(backbone.client(t, securedAdministrator, backbone.administrator.Password))

	for name, everyone := range map[string]*kadm.ACLBuilder{
		"seeing a topic":                  kadm.NewACLs().Allow("User:*").AllowHosts("*").Topics(topology.Agents.Name).Operations(kadm.OpWrite),
		"reading a topic's configuration": kadm.NewACLs().Allow("User:*").AllowHosts("*").Topics(topology.Agents.Name).Operations(kadm.OpDescribeConfigs),
		"joining a component's group":     kadm.NewACLs().Allow("User:*").AllowHosts("*").Groups(broker.EventWriter.Group()).Operations(kadm.OpRead),
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if added, err := admin.CreateACLs(ctx, everyone); firstRefusal(added, err) != nil {
			cancel()
			t.Fatalf("grant everyone %s: %v", name, firstRefusal(added, err))
		}
		_, err := provisioner.ApplyGrants(ctx, grants, passwords)
		if err == nil || !strings.Contains(err.Error(), "to less than its grant") {
			t.Errorf("a backbone that grants every principal %s was answered %v", name, err)
		}
		if _, err := admin.DeleteACLs(ctx, everyone); err != nil {
			t.Fatalf("take back what everyone was granted: %v", err)
		}
		cancel()
	}
}

func TestARefusalIsNamedInReadinessAndCountedByWhatWasRefused(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	_, _, passwords := grantedOn(t, backbone, topology)

	registry := platformmetrics.New("integration-test")
	denials := broker.NewDenials(registry)

	wrong := backbone.as(broker.EventWriter, config.Secret("not the event writer's password")).Observed(denials)
	impostor, err := broker.NewStateLog(broker.Config{Brokers: backbone.addresses, Topic: topology.Events.Name, ClientID: "integration-test", Security: wrong}, 10)
	if err != nil {
		t.Fatalf("build a reader with a wrong password: %v", err)
	}
	defer impostor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := impostor.Ping(ctx); !errors.Is(err, broker.ErrNotAuthenticated) {
		t.Errorf("a wrong password reached readiness as %v", err)
	}
	if err := denials.Check(ctx); !errors.Is(err, broker.ErrNotAuthenticated) {
		t.Errorf("the refused credentials reached readiness as %v", err)
	}

	alert := backbone.as(broker.AlertWriter, passwords[broker.AlertWriter]).Observed(denials)
	trespasser, err := broker.NewStateLog(broker.Config{Brokers: backbone.addresses, Topic: topology.Agents.Name, ClientID: "integration-test", Security: alert}, 10)
	if err != nil {
		t.Fatalf("build a reader of a topic the alert writer is not granted: %v", err)
	}
	defer trespasser.Close()
	if _, err := trespasser.VerifyTopics(ctx, topology.Agents); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("verifying a topic outside the grant was answered %v", err)
	}
	quarantine, err := broker.NewQuarantine(broker.Config{
		Brokers: backbone.addresses, Topic: topology.Agents.Name, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test", Security: alert,
	})
	if err != nil {
		t.Fatalf("build a writer of a topic the alert writer is not granted: %v", err)
	}
	defer quarantine.Close()
	if err := quarantine.Publish(ctx, []broker.Refused{{Key: []byte("agent"), Value: []byte("probe"), Reason: "probe"}}); err == nil {
		t.Error("the alert writer wrote a topic it is not granted")
	}
	if err := denials.Check(ctx); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("the refused write reached readiness as %v", err)
	}
	if err := denials.Check(ctx); err != nil {
		t.Errorf("a look that found no new refusal still failed: %v", err)
	}

	if err := trespasser.Replay(ctx, func(context.Context, []broker.Record) error { return nil }); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("replaying a topic outside the grant was answered %v", err)
	}
	if err := denials.Check(ctx); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("the refused end of the log reached readiness as %v", err)
	}
	if err := trespasser.Follow(ctx, func(context.Context, []broker.Record) error { return nil }); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("following a topic outside the grant was answered %v", err)
	}
	if err := denials.Check(ctx); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("the refused read reached readiness as %v", err)
	}

	admin := kadm.NewClient(backbone.client(t, securedAdministrator, backbone.administrator.Password))
	narrowed := kadm.NewACLs().Allow(broker.AlertWriter.Principal()).AllowHosts("*").Topics(topology.Detections.Name).Operations(kadm.OpDescribeConfigs)
	if _, err := admin.DeleteACLs(ctx, narrowed); err != nil {
		t.Fatalf("take back the alert writer's reading of the detections topic's configuration: %v", err)
	}
	reader, err := broker.NewStateLog(broker.Config{Brokers: backbone.addresses, Topic: topology.Detections.Name, ClientID: "integration-test", Security: alert}, 10)
	if err != nil {
		t.Fatalf("build a reader of the detections: %v", err)
	}
	defer reader.Close()
	if _, err := reader.VerifyTopics(ctx, topology.Detections); !errors.Is(err, broker.ErrNotAuthorized) {
		t.Errorf("verifying a topic whose configuration the grant no longer reads was answered %v", err)
	}
}

func TestTheSecuredBackboneAdmitsNoAnonymousOrPlaintextClient(t *testing.T) {
	backbone := secured(t)
	authority, err := os.ReadFile(backbone.authority)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority)
	for name, options := range map[string][]kgo.Opt{
		"anonymous over tls": {kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool})},
		"plaintext":          {kgo.SASL(scram.Auth{User: securedAdministrator, Pass: backbone.administrator.Password.Reveal()}.AsSha256Mechanism())},
	} {
		client, err := kgo.NewClient(append([]kgo.Opt{kgo.SeedBrokers(backbone.addresses...), kgo.RequestRetries(0)}, options...)...)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Ping(ctx); err == nil {
			t.Errorf("a %s client reached the backbone", name)
		}
		cancel()
		client.Close()
	}
}

func TestARefusedReadIsCountedWhileTheConsumerKeepsAsking(t *testing.T) {
	backbone := secured(t)
	topology := securedTopology(t)
	_, _, passwords := grantedOn(t, backbone, topology)

	registry := platformmetrics.New("integration-test")
	denials := broker.NewDenials(registry)
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      backbone.addresses,
		Topics:       []string{topology.Agents.Name},
		Group:        broker.AlertWriter.Group(),
		ClientID:     "integration-test",
		MaxRecords:   10,
		FetchMaxWait: 100 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(registry),
		Security:     backbone.as(broker.AlertWriter, passwords[broker.AlertWriter]).Observed(denials),
	})
	if err != nil {
		t.Fatalf("build a consumer of a topic the alert writer is not granted: %v", err)
	}
	defer consumer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = consumer.Consume(ctx, func(context.Context, []broker.Record) error { return nil }) }()
	for ctx.Err() == nil {
		if err := denials.Check(ctx); err != nil {
			if !errors.Is(err, broker.ErrNotAuthorized) {
				t.Errorf("a refused read reached readiness as %v", err)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Error("the consumer read a topic it is not granted and nothing was refused")
}
