package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

func main() {
	endpoint := flag.String("endpoint", "https://127.0.0.1:8443", "gateway base URL")
	huntEndpoint := flag.String("hunt", "", "query plane base URL; asks what was stored instead of sending a batch")
	alertEndpoint := flag.String("alerts", "", "control plane base URL; works an alert through its lifecycle instead of sending a batch")
	window := flag.Duration("window", time.Hour, "how far back a hunt looks")
	pki := flag.String("pki", ".local/pki", "directory holding the development material")
	batchID := flag.String("batch-id", "probe-0001", "batch identifier")
	eventID := flag.String("event-id", "99999999-8888-4777-8666-555555555555", "event identifier")
	outcome := flag.String("outcome", "failure", "authentication outcome the sample event carries: failure or success")
	flag.Parse()

	run := func() error { return probe(*endpoint, *pki, *batchID, *eventID, *outcome) }
	if *huntEndpoint != "" {
		run = func() error { return ask(*huntEndpoint, *pki, *window) }
	}
	if *alertEndpoint != "" {
		run = func() error { return triage(*alertEndpoint, *pki) }
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "devprobe: %v\n", err)
		os.Exit(1)
	}
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
	client, err := speaker(pki, "admin")
	if err != nil {
		return err
	}

	status, body, err := post(client, endpoint+control.SessionPath, control.ContentType, &controlv1.SessionRequest{})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return refused("session", status, body)
	}
	var opened controlv1.SessionResponse
	if err := proto.Unmarshal(body, &opened); err != nil {
		return err
	}
	fmt.Printf("session %s for %s\n", opened.GetSession().GetId(), opened.GetSession().GetGrant().GetSubject())

	status, body, err = send(client, http.MethodPost, endpoint+control.AlertSearch, opened.GetToken(),
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
	return walk(client, endpoint, opened.GetToken(), page.GetAlerts()[0].GetAlertId())
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

func speaker(pki, name string) (*http.Client, error) {
	authority, err := os.ReadFile(pki + "/agent-ca.pem")
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

func probe(endpoint, pki, batchID, eventID, outcome string) error {
	client, err := speaker(pki, "agent")
	if err != nil {
		return err
	}

	encoded, err := proto.Marshal(sample(batchID, eventID, outcome))
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint+ingest.EventsPath, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", ingest.ContentType)

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	fmt.Printf("status %d\n", response.StatusCode)
	if response.StatusCode == http.StatusOK {
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
