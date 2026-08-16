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

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	"github.com/dynasmon/Seagull-v2/internal/event"
	"github.com/dynasmon/Seagull-v2/internal/ingest"
	"github.com/dynasmon/Seagull-v2/internal/protocol"
)

func main() {
	endpoint := flag.String("endpoint", "https://127.0.0.1:8443", "gateway base URL")
	pki := flag.String("pki", ".local/pki", "directory holding the development material")
	batchID := flag.String("batch-id", "probe-0001", "batch identifier")
	eventID := flag.String("event-id", "99999999-8888-4777-8666-555555555555", "event identifier")
	flag.Parse()

	if err := probe(*endpoint, *pki, *batchID, *eventID); err != nil {
		fmt.Fprintf(os.Stderr, "devprobe: %v\n", err)
		os.Exit(1)
	}
}

func probe(endpoint, pki, batchID, eventID string) error {
	authority, err := os.ReadFile(pki + "/agent-ca.pem")
	if err != nil {
		return err
	}
	keypair, err := tls.LoadX509KeyPair(pki+"/agent.pem", pki+"/agent-key.pem")
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority) {
		return fmt.Errorf("authority certificate is unusable")
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS13,
		}},
		Timeout: 15 * time.Second,
	}

	encoded, err := proto.Marshal(sample(batchID, eventID))
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

func sample(batchID, eventID string) *ingestv1.EventBatch {
	now := timestamppb.New(time.Now().UTC())
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
				Outcome:       eventv1.Outcome_OUTCOME_FAILURE,
				OutcomeReason: "failed_password",
				Method:        "password",
				User:          &eventv1.User{Name: "root"},
				Service:       &eventv1.Service{Name: "sshd", Protocol: "ssh"},
				Network: &eventv1.Network{
					Source:      &eventv1.Endpoint{Ip: "203.0.113.10", Port: 54321},
					Destination: &eventv1.Endpoint{Ip: "198.51.100.5", Port: 22},
					Transport:   eventv1.Transport_TRANSPORT_TCP,
				},
				RawRecord: "Failed password for root from 203.0.113.10 port 54321 ssh2",
			}},
		}},
	}
}
