package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

func main() {
	endpoint := flag.String("endpoint", "https://127.0.0.1:8443", "gateway base URL")
	registry := flag.String("register", "https://127.0.0.1:8445", "control plane base URL the development agent is registered with before a batch is sent; empty skips it")
	huntEndpoint := flag.String("hunt", "", "query plane base URL; asks what was stored instead of sending a batch")
	alertEndpoint := flag.String("alerts", "", "control plane base URL; works an alert through its lifecycle instead of sending a batch")
	incidentEndpoint := flag.String("incidents", "", "control plane base URL; reads a correlated story back to its events and works it")
	agentEndpoint := flag.String("agents", "", "control plane base URL; registers an agent, has its certificate issued and renewed, and revokes it")
	renewalEndpoint := flag.String("renewals", "https://127.0.0.1:8446", "agent-facing control plane base URL the registry probe renews against")
	agentID := flag.String("agent-id", "probe-agent-01", "agent the registry probe registers")
	window := flag.Duration("window", time.Hour, "how far back a hunt looks")
	pki := flag.String("pki", ".local/pki", "directory holding the development material")
	batchID := flag.String("batch-id", "probe-0001", "batch identifier")
	eventID := flag.String("event-id", "99999999-8888-4777-8666-555555555555", "event identifier")
	outcome := flag.String("outcome", "failure", "authentication outcome the sample event carries: failure or success")
	flag.Parse()

	run := func() error { return probe(*endpoint, *registry, *pki, *batchID, *eventID, *outcome) }
	if *huntEndpoint != "" {
		run = func() error { return ask(*huntEndpoint, *pki, *window) }
	}
	if *alertEndpoint != "" {
		run = func() error { return triage(*alertEndpoint, *pki) }
	}
	if *incidentEndpoint != "" {
		run = func() error { return investigate(*incidentEndpoint, *pki) }
	}
	if *agentEndpoint != "" {
		run = func() error { return enrol(*agentEndpoint, *renewalEndpoint, *pki, *agentID) }
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "devprobe: %v\n", err)
		os.Exit(1)
	}
}

func enrol(endpoint, renewalEndpoint, pki, agentID string) error {
	client, token, err := authenticate(endpoint, pki)
	if err != nil {
		return err
	}

	status, body, err := send(client, http.MethodPost, endpoint+control.AgentsPath, token, &agentv1.Registration{
		AgentId:      agentID,
		TenantId:     "default",
		Platform:     &agentv1.Platform{Os: "linux", Architecture: "amd64", Hostname: agentID + ".dev"},
		AgentVersion: "2.0.0",
		Note:         "registered by devprobe",
	})
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusConflict {
		return refused("register", status, body)
	}
	fmt.Printf("register status %d\n", status)

	key, requestPEM, err := keyAndRequest(agentID)
	if err != nil {
		return err
	}
	status, body, err = send(client, http.MethodPost, endpoint+"/v1/agents/"+agentID+"/certificate", token,
		&agentv1.CertificateRequest{CsrPem: requestPEM, Note: "issued by devprobe"})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return refused("issue", status, body)
	}
	var issued agentv1.IssuedCertificate
	if err := proto.Unmarshal(body, &issued); err != nil {
		return err
	}
	fmt.Printf("issued %s serial %s expires %s\n", issued.GetIdentity().GetSubject(),
		issued.GetIdentity().GetSerial(), issued.GetIdentity().GetExpiresAt().AsTime().Format(time.RFC3339))

	if err := renew(renewalEndpoint, agentID, key, &issued); err != nil {
		return err
	}

	status, body, err = send(client, http.MethodPost, endpoint+control.AgentSearch, token, &agentv1.Query{Limit: 10})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("search", status, body)
	}
	var page agentv1.Page
	if err := proto.Unmarshal(body, &page); err != nil {
		return err
	}
	fmt.Printf("agents %d\n", len(page.GetAgents()))
	for _, one := range page.GetAgents() {
		seen := "never"
		if one.GetLastSeen() != nil {
			seen = one.GetLastSeen().AsTime().Format(time.RFC3339)
		}
		fmt.Printf("  %s %s %s last seen %s\n", one.GetAgentId(), one.GetState(), one.GetTenantId(), seen)
	}

	status, body, err = send(client, http.MethodPost, endpoint+"/v1/agents/"+agentID+"/transition", token,
		&agentv1.TransitionRequest{To: agentv1.State_STATE_REVOKED, Note: "the devprobe run is over"})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("revoke", status, body)
	}
	var revoked agentv1.Agent
	if err := proto.Unmarshal(body, &revoked); err != nil {
		return err
	}
	fmt.Printf("revoked %s state %s revision %d\n", revoked.GetAgentId(), revoked.GetState(), revoked.GetRevision())

	status, body, err = send(client, http.MethodGet, endpoint+"/v1/agents/"+agentID+"/history", token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("history", status, body)
	}
	var history agentv1.History
	if err := proto.Unmarshal(body, &history); err != nil {
		return err
	}
	status, body, err = send(client, http.MethodGet, endpoint+"/v1/agents/"+agentID+"/certificates", token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("certificates", status, body)
	}
	var signed agentv1.CertificateHistory
	if err := proto.Unmarshal(body, &signed); err != nil {
		return err
	}
	fmt.Printf("certificates %d\n", len(signed.GetCertificates()))
	for _, one := range signed.GetCertificates() {
		current := "current"
		if one.GetSupersededAt() != nil {
			current = "superseded " + one.GetSupersededAt().AsTime().Format(time.RFC3339)
		}
		fmt.Printf("  %s by %s from %s: %s\n", one.GetIdentity().GetSerial(), one.GetIssuedBy(),
			one.GetAuthoritySubject(), current)
	}

	fmt.Printf("trail %d\n", len(history.GetTransitions()))
	for _, line := range history.GetTransitions() {
		fmt.Printf("  %d %s -> %s by %s: %s\n", line.GetRevision(), line.GetFrom(), line.GetTo(),
			line.GetActor(), line.GetNote())
	}
	return nil
}

// The query plane authorises by certificate, so this speaks as the caller
// `make dev-pki` mints rather than as the agent.
func ask(endpoint, pki string, window time.Duration) error {
	client, err := speaker(pki, "caller")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	query := &huntv1.Query{
		Range: &huntv1.TimeRange{Start: timestamppb.New(now.Add(-window)), End: timestamppb.New(now)},
		Limit: 5,
	}

	for _, path := range []string{hunt.EventsPath, hunt.DetectionsPath} {
		status, body, err := post(client, endpoint+path, hunt.ContentType, query)
		if err != nil {
			return err
		}
		fmt.Printf("%s status %d\n", path, status)

		if status != http.StatusOK {
			var refusal huntv1.Refusal
			if err := proto.Unmarshal(body, &refusal); err != nil {
				return err
			}
			fmt.Printf("refusal %s", prototext.Format(&refusal))
			continue
		}
		if err := report(path, body); err != nil {
			return err
		}
	}
	return nil
}

func report(path string, body []byte) error {
	if path == hunt.DetectionsPath {
		var page huntv1.DetectionPage
		if err := proto.Unmarshal(body, &page); err != nil {
			return err
		}
		fmt.Printf("detections %d\n", len(page.GetDetections()))
		for _, made := range page.GetDetections() {
			fmt.Printf("  %s %s %s\n", made.GetEventTime().AsTime().Format(time.RFC3339),
				made.GetRule().GetId(), made.GetSeverity())
		}
		return nil
	}

	var page huntv1.EventPage
	if err := proto.Unmarshal(body, &page); err != nil {
		return err
	}
	fmt.Printf("events %d\n", len(page.GetEvents()))
	for _, record := range page.GetEvents() {
		fmt.Printf("  %s %s %s\n", record.GetTime().GetEventTime().AsTime().Format(time.RFC3339),
			record.GetEventId(), record.GetAuthentication().GetUser().GetName())
	}
	return nil
}

// The control plane exchanges a completed handshake for a session and decides
// every request against the policy, so this speaks as the administrator
// `make dev-pki` mints and carries the token it is given.
func triage(endpoint, pki string) error {
	client, token, err := authenticate(endpoint, pki)
	if err != nil {
		return err
	}

	status, body, err := send(client, http.MethodPost, endpoint+control.AlertSearch, token,
		&alertv1.Query{States: []alertv1.State{alertv1.State_STATE_OPEN}, Limit: 5})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("search", status, body)
	}
	var page alertv1.Page
	if err := proto.Unmarshal(body, &page); err != nil {
		return err
	}

	fmt.Printf("open alerts %d\n", len(page.GetAlerts()))
	for _, one := range page.GetAlerts() {
		fmt.Printf("  %s %s %s %s\n", one.GetRaisedAt().AsTime().Format(time.RFC3339),
			one.GetAlertId(), one.GetRule().GetId(), one.GetSeverity())
	}
	if len(page.GetAlerts()) == 0 {
		return nil
	}
	return walk(client, endpoint, token, page.GetAlerts()[0].GetAlertId())
}

func authenticate(endpoint, pki string) (*http.Client, string, error) {
	client, err := speaker(pki, "admin")
	if err != nil {
		return nil, "", err
	}

	status, body, err := post(client, endpoint+control.SessionPath, control.ContentType, &controlv1.SessionRequest{})
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusCreated {
		return nil, "", refused("session", status, body)
	}
	var opened controlv1.SessionResponse
	if err := proto.Unmarshal(body, &opened); err != nil {
		return nil, "", err
	}
	fmt.Printf("session %s for %s\n", opened.GetSession().GetId(), opened.GetSession().GetGrant().GetSubject())
	return client, opened.GetToken(), nil
}

// A story needs a rule that orders events and two events to order, so this
// answers after `-outcome failure` and then `-outcome success` have both
// reached the gateway from the same address inside the rule's window.
func investigate(endpoint, pki string) error {
	client, token, err := authenticate(endpoint, pki)
	if err != nil {
		return err
	}

	status, body, err := send(client, http.MethodPost, endpoint+control.IncidentSearch, token,
		&incidentv1.Query{States: []incidentv1.State{incidentv1.State_STATE_OPEN}, Limit: 5})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("search", status, body)
	}
	var page incidentv1.Page
	if err := proto.Unmarshal(body, &page); err != nil {
		return err
	}

	fmt.Printf("open incidents %d\n", len(page.GetIncidents()))
	for _, one := range page.GetIncidents() {
		fmt.Printf("  %s %s %s %s confidence=%s\n", one.GetRaisedAt().AsTime().Format(time.RFC3339),
			one.GetIncidentId(), one.GetRule().GetId(), one.GetSeverity(), incident.Level(one.GetConfidence()))
		for _, stage := range one.GetStages() {
			fmt.Printf("    %s %s %s\n", stage.GetEventTime().AsTime().Format(time.RFC3339),
				stage.GetName(), stage.GetEventId())
		}
		for _, about := range one.GetGroup() {
			fmt.Printf("    about %s=%s\n", about.GetField(), about.GetValue())
		}
	}
	if len(page.GetIncidents()) == 0 {
		return nil
	}
	return follow(client, endpoint, token, page.GetIncidents()[0].GetIncidentId())
}

func follow(client *http.Client, endpoint, token, id string) error {
	for _, step := range []*incidentv1.TransitionRequest{
		{To: incidentv1.State_STATE_ACKNOWLEDGED},
		{To: incidentv1.State_STATE_IN_INVESTIGATION, Note: "checking what the session did after it was accepted"},
		{To: incidentv1.State_STATE_RESOLVED, Note: "the account was rotated"},
	} {
		status, body, err := send(client, http.MethodPost, endpoint+"/v1/incidents/"+id+"/transition", token, step)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return refused("transition", status, body)
		}
		var moved incidentv1.Incident
		if err := proto.Unmarshal(body, &moved); err != nil {
			return err
		}
		fmt.Printf("  -> %s at revision %d by %s\n", moved.GetState(), moved.GetRevision(), moved.GetChangedBy())
	}

	status, body, err := send(client, http.MethodGet, endpoint+"/v1/incidents/"+id+"/history", token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("history", status, body)
	}
	var trail incidentv1.History
	if err := proto.Unmarshal(body, &trail); err != nil {
		return err
	}

	fmt.Printf("trail %d\n", len(trail.GetTransitions()))
	for _, line := range trail.GetTransitions() {
		fmt.Printf("  %d %s -> %s by %s %q\n", line.GetRevision(), line.GetFrom(), line.GetTo(), line.GetActor(), line.GetNote())
	}
	return nil
}

func walk(client *http.Client, endpoint, token, id string) error {
	for _, step := range []*alertv1.TransitionRequest{
		{To: alertv1.State_STATE_ACKNOWLEDGED},
		{To: alertv1.State_STATE_IN_INVESTIGATION, Note: "checking whether the source is ours"},
		{To: alertv1.State_STATE_FALSE_POSITIVE, Note: "the scanner is ours"},
	} {
		status, body, err := send(client, http.MethodPost, endpoint+"/v1/alerts/"+id+"/transition", token, step)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return refused("transition", status, body)
		}
		var moved alertv1.Alert
		if err := proto.Unmarshal(body, &moved); err != nil {
			return err
		}
		fmt.Printf("  -> %s at revision %d by %s\n", moved.GetState(), moved.GetRevision(), moved.GetChangedBy())
	}

	status, body, err := send(client, http.MethodGet, endpoint+"/v1/alerts/"+id+"/history", token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refused("history", status, body)
	}
	var trail alertv1.History
	if err := proto.Unmarshal(body, &trail); err != nil {
		return err
	}

	fmt.Printf("trail %d\n", len(trail.GetTransitions()))
	for _, line := range trail.GetTransitions() {
		fmt.Printf("  %d %s -> %s by %s %q\n", line.GetRevision(), line.GetFrom(), line.GetTo(), line.GetActor(), line.GetNote())
	}
	return nil
}

func refused(what string, status int, body []byte) error {
	var refusal controlv1.Refusal
	if err := proto.Unmarshal(body, &refusal); err != nil {
		return fmt.Errorf("%s answered %d", what, status)
	}
	return fmt.Errorf("%s answered %d: %s %s", what, status, refusal.GetCode(), refusal.GetDetail())
}

func send(client *http.Client, method, url, token string, message proto.Message) (int, []byte, error) {
	var payload []byte
	if message != nil {
		encoded, err := proto.Marshal(message)
		if err != nil {
			return 0, nil, err
		}
		payload = encoded
	}

	request, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", control.ContentType)
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, body, nil
}

func post(client *http.Client, url, contentType string, message proto.Message) (int, []byte, error) {
	encoded, err := proto.Marshal(message)
	if err != nil {
		return 0, nil, err
	}
	response, err := client.Post(url, contentType, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, body, nil
}

// An agent verifies the gateway with the agent authority, and a person verifies
// the control and query planes with the operator one. The two are separate
// trust domains, so neither identity can be presented to the other's plane.
func trustedBy(name string) string {
	if name == "agent" {
		return "agent-ca.pem"
	}
	return "operator-ca.pem"
}

func speaker(pki, name string) (*http.Client, error) {
	authority, err := os.ReadFile(filepath.Join(pki, trustedBy(name)))
	if err != nil {
		return nil, err
	}
	keypair, err := tls.LoadX509KeyPair(pki+"/"+name+".pem", pki+"/"+name+"-key.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority) {
		return nil, fmt.Errorf("authority certificate is unusable")
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS13,
		}},
		Timeout: 30 * time.Second,
	}, nil
}

func probe(endpoint, registry, pki, batchID, eventID, outcome string) error {
	client, err := speaker(pki, "agent")
	if err != nil {
		return err
	}
	if registry != "" {
		if err := register(registry, pki); err != nil {
			return err
		}
	}

	encoded, err := proto.Marshal(sample(batchID, eventID, outcome))
	if err != nil {
		return err
	}
	status, body, err := deliver(client, endpoint, encoded)
	for attempt := 1; registry != "" && err == nil && attempt < 40 && unregistered(status, body); attempt++ {
		time.Sleep(250 * time.Millisecond)
		status, body, err = deliver(client, endpoint, encoded)
	}
	if err != nil {
		return err
	}

	fmt.Printf("status %d\n", status)
	if status == http.StatusOK {
		var acknowledgement ingestv1.BatchAck
		if err := proto.Unmarshal(body, &acknowledgement); err != nil {
			return err
		}
		fmt.Printf("ack %s", prototext.Format(&acknowledgement))
		return nil
	}

	var rejection ingestv1.Rejection
	if err := proto.Unmarshal(body, &rejection); err != nil {
		return err
	}
	fmt.Printf("rejection %s", prototext.Format(&rejection))
	return nil
}

func deliver(client *http.Client, endpoint string, encoded []byte) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint+ingest.EventsPath, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", ingest.ContentType)

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, body, nil
}

func unregistered(status int, body []byte) bool {
	if status != http.StatusForbidden {
		return false
	}
	var rejection ingestv1.Rejection
	return proto.Unmarshal(body, &rejection) == nil && rejection.GetCode() == ingest.CodeNotRegistered
}

func register(endpoint, pki string) error {
	agentID, err := subjectOf(filepath.Join(pki, "agent.pem"))
	if err != nil {
		return err
	}
	client, token, err := authenticate(endpoint, pki)
	if err != nil {
		return err
	}

	status, body, err := send(client, http.MethodPost, endpoint+control.AgentsPath, token, &agentv1.Registration{
		AgentId:  agentID,
		TenantId: "default",
		Platform: &agentv1.Platform{Os: "linux", Architecture: "amd64", Hostname: "probe-host"},
		Note:     "registered by devprobe",
	})
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusConflict {
		return refused("register", status, body)
	}
	fmt.Printf("register %s status %d\n", agentID, status)
	return nil
}

func subjectOf(path string) (string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		return "", fmt.Errorf("%s holds no certificate", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return certificate.Subject.CommonName, nil
}

func sample(batchID, eventID, outcome string) *ingestv1.EventBatch {
	now := timestamppb.New(time.Now().UTC())
	held, reason := eventv1.Outcome_OUTCOME_FAILURE, "failed_password"
	if outcome == "success" {
		held, reason = eventv1.Outcome_OUTCOME_SUCCESS, "accepted_password"
	}
	return &ingestv1.EventBatch{
		BatchId:         batchID,
		ProtocolVersion: protocol.Version,
		Events: []*eventv1.Event{{
			EventId:       eventID,
			SchemaVersion: event.SchemaVersion,
			EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
			Time:          &eventv1.Timestamps{EventTime: now, ObservedTime: now},
			Origin: &eventv1.Origin{
				AgentId: "ignored-by-the-gateway",
				Host:    &eventv1.Host{Hostname: "probe-host", Os: "linux", Architecture: "amd64"},
			},
			Collection: &eventv1.Collection{Collector: "ssh.authlog", Source: "/var/log/auth.log", Sequence: 1},
			Body: &eventv1.Event_Authentication{Authentication: &eventv1.Authentication{
				Activity:      eventv1.Authentication_ACTIVITY_LOGON,
				Outcome:       held,
				OutcomeReason: reason,
				Method:        "password",
				User:          &eventv1.User{Name: "root"},
				Service:       &eventv1.Service{Name: "sshd", Protocol: "ssh"},
				Network: &eventv1.Network{
					Source:      &eventv1.Endpoint{Ip: "203.0.113.10", Port: 54321},
					Destination: &eventv1.Endpoint{Ip: "198.51.100.5", Port: 22},
					Transport:   eventv1.Transport_TRANSPORT_TCP,
				},
				RawRecord: fmt.Sprintf("%s password for root from 203.0.113.10 port 54321 ssh2", outcome),
			}},
		}},
	}
}

func keyAndRequest(agentID string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate an agent key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create a certificate request: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// The agent half: the certificate that was just issued is what authenticates the
// request for the next one, so no operator is involved and nothing but the wire
// is used to prove who is asking.
func renew(endpoint, agentID string, key *ecdsa.PrivateKey, issued *agentv1.IssuedCertificate) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode the agent key: %w", err)
	}
	keypair, err := tls.X509KeyPair(
		append(append([]byte(nil), issued.GetCertificatePem()...), issued.GetChainPem()...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		return fmt.Errorf("load the issued keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(issued.GetTrustBundlePem()) {
		return errors.New("the bundle the agent was told to trust holds no authority")
	}

	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{keypair},
	}}}
	defer client.CloseIdleConnections()

	_, requestPEM, err := keyAndRequest(agentID)
	if err != nil {
		return err
	}
	status, body, err := send(client, http.MethodPost, endpoint+control.RenewalPath, "",
		&agentv1.RenewalRequest{CsrPem: requestPEM})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return refused("renew", status, body)
	}
	var renewed agentv1.IssuedCertificate
	if err := proto.Unmarshal(body, &renewed); err != nil {
		return err
	}
	fmt.Printf("renewed %s serial %s expires %s\n", renewed.GetIdentity().GetSubject(),
		renewed.GetIdentity().GetSerial(), renewed.GetIdentity().GetExpiresAt().AsTime().Format(time.RFC3339))
	return nil
}
