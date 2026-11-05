package e2e_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
)

const (
	answersVariable = "SEAGULL_RECORD_AGENT_ANSWERS"
	contractsModule = "github.com/dynasmon/Seagull-contracts"
)

var answersDirectory = filepath.Join("testdata", "agent", fmt.Sprintf("protocol-%d", protocol.Version))

// One answer an agent reads, as the listener gave it. What the summary holds is
// what an agent may depend on; what changes from one recording to the next — a
// key, a serial, an instant, the bytes a signature makes — is named by its shape.
type recordedAnswer struct {
	Name        string `json:"name"`
	Listener    string `json:"listener"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Request     string `json:"request,omitempty"`
	Asked       string `json:"asked,omitempty"`
	IfNoneMatch bool   `json:"if_none_match,omitempty"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	RetryAfter  bool   `json:"retry_after,omitempty"`
	Tagged      bool   `json:"tagged,omitempty"`
	Reply       string `json:"reply,omitempty"`
	Message     string `json:"message,omitempty"`
	Summary     any    `json:"summary,omitempty"`
}

type answerBook struct {
	Protocol  uint32           `json:"protocol"`
	Contracts string           `json:"contracts"`
	Answers   []recordedAnswer `json:"answers"`
	files     map[string][]byte
}

func newAnswerBook(t *testing.T) *answerBook {
	t.Helper()
	return &answerBook{Protocol: protocol.Version, Contracts: required(t, contractsModule), files: map[string][]byte{}}
}

func required(t *testing.T, module string) string {
	t.Helper()
	declared, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read the module the platform is built from: %v", err)
	}
	for _, line := range strings.Split(string(declared), "\n") {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(fields) >= 2 && fields[0] == module {
			return fields[1]
		}
	}
	t.Fatalf("the platform requires no %s", module)
	return ""
}

// One request an agent, or the operator acting for it, sends: reply names what
// the agent reads at that route and status, or nil to keep only the bytes.
type asking struct {
	name, listener   string
	client           *http.Client
	method, url      string
	body             []byte
	contentType, tag string
	bearer           string
	reply            func(status int) proto.Message
}

func encoded(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (b *answerBook) ask(t *testing.T, given asking) *http.Response {
	t.Helper()
	if slices.ContainsFunc(b.Answers, func(held recordedAnswer) bool { return held.Name == given.name }) {
		t.Fatalf("two answers are named %s", given.name)
	}
	asked, err := http.NewRequest(given.method, given.url, bytes.NewReader(given.body))
	if err != nil {
		t.Fatal(err)
	}
	if given.contentType != "" {
		asked.Header.Set("Content-Type", given.contentType)
	}
	if given.tag != "" {
		asked.Header.Set("If-None-Match", given.tag)
	}
	if given.bearer != "" {
		asked.Header.Set("Authorization", "Bearer "+given.bearer)
	}
	response, err := given.client.Do(asked)
	if err != nil {
		t.Fatalf("%s: %v", given.name, err)
	}
	defer response.Body.Close()
	answered, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	held := recordedAnswer{
		Name: given.name, Listener: given.listener, Method: given.method, Path: asked.URL.Path,
		IfNoneMatch: given.tag != "", Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"),
		RetryAfter: response.Header.Get("Retry-After") != "", Tagged: response.Header.Get("ETag") != "",
	}
	if len(given.body) > 0 {
		held.Request, held.Asked = given.name+".request.pb", given.contentType
		b.files[held.Request] = given.body
	}
	if len(answered) > 0 {
		held.Reply = given.name + ".reply.pb"
		b.files[held.Reply] = answered
		if given.reply != nil {
			if decoded := given.reply(response.StatusCode); decoded != nil {
				if err := proto.Unmarshal(answered, decoded); err != nil {
					t.Fatalf("%s was answered %d with what does not read as %s: %v", given.name, response.StatusCode, decoded.ProtoReflect().Descriptor().FullName(), err)
				}
				held.Message = string(decoded.ProtoReflect().Descriptor().FullName())
				held.Summary = summarize(decoded.ProtoReflect())
			}
		}
	}
	b.Answers = append(b.Answers, held)
	return response
}

// A recording is written only when asked for; otherwise every answer is held to
// the one recorded, and a change fails until it is recorded again on purpose.
func (b *answerBook) settle(t *testing.T) {
	t.Helper()
	if into := os.Getenv(answersVariable); into != "" {
		b.write(t, into)
		return
	}
	committed, err := os.ReadFile(filepath.Join(answersDirectory, "answers.json"))
	if err != nil {
		t.Fatalf("read the recorded answers: %v; record them with make record-agent-answers", err)
	}
	var recorded answerBook
	if err := json.Unmarshal(committed, &recorded); err != nil {
		t.Fatalf("decode the recorded answers: %v", err)
	}
	if recorded.Protocol != b.Protocol || recorded.Contracts != b.Contracts {
		t.Errorf("the answers were recorded for protocol %d and contracts %s, and this platform speaks %d with %s: record them again with make record-agent-answers",
			recorded.Protocol, recorded.Contracts, b.Protocol, b.Contracts)
	}
	given := map[string]recordedAnswer{}
	for _, answer := range b.Answers {
		given[answer.Name] = answer
	}
	for _, held := range recorded.Answers {
		answer, found := given[held.Name]
		if !found {
			t.Errorf("%s was recorded and is no longer asked", held.Name)
			continue
		}
		delete(given, held.Name)
		if was, now := canonical(t, held), canonical(t, answer); was != now {
			t.Errorf("an agent-visible answer changed: %s\n  recorded %s\n  given    %s\nan answer changes only with a protocol or schema decision (ADR 48); record it again with make record-agent-answers", held.Name, was, now)
		}
		for _, file := range []string{held.Request, held.Reply} {
			if file == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(answersDirectory, file)); err != nil {
				t.Errorf("%s is recorded without %s", held.Name, file)
			}
		}
	}
	for name := range given {
		t.Errorf("%s is asked and was never recorded: record the answers with make record-agent-answers", name)
	}
}

func (b *answerBook) write(t *testing.T, into string) {
	t.Helper()
	if err := os.RemoveAll(into); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(into, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range b.files {
		if err := os.WriteFile(filepath.Join(into, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(into, "answers.json"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d answers into %s", len(b.Answers), into)
}

func canonical(t *testing.T, answer recordedAnswer) string {
	t.Helper()
	answer.Request, answer.Reply = "", ""
	encoded, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	stable, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return string(stable)
}

var volatileText = []string{"serial", "fingerprint_sha256", "key_id", "keyid", "batch_id", "assessment_id", "digest", "sha256", "detail"}

func summarize(message protoreflect.Message) map[string]any {
	held := map[string]any{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList():
			var items []any
			list := value.List()
			for index := range list.Len() {
				items = append(items, element(field, list.Get(index)))
			}
			held[string(field.Name())] = items
		case field.IsMap():
			entries := map[string]any{}
			value.Map().Range(func(key protoreflect.MapKey, entry protoreflect.Value) bool {
				entries[key.String()] = element(field.MapValue(), entry)
				return true
			})
			held[string(field.Name())] = entries
		default:
			held[string(field.Name())] = element(field, value)
		}
		return true
	})
	return held
}

func element(field protoreflect.FieldDescriptor, value protoreflect.Value) any {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		switch field.Message().FullName() {
		case "google.protobuf.Timestamp":
			return "<instant>"
		case "google.protobuf.Duration":
			var held durationpb.Duration
			proto.Merge(&held, value.Message().Interface())
			return held.AsDuration().String()
		}
		return summarize(value.Message())
	case protoreflect.BytesKind:
		return shapeOf(value.Bytes())
	case protoreflect.EnumKind:
		if named := field.Enum().Values().ByNumber(value.Enum()); named != nil {
			return string(named.Name())
		}
		return value.Enum()
	case protoreflect.StringKind:
		if slices.Contains(volatileText, string(field.Name())) {
			return "<" + string(field.Name()) + ">"
		}
		return value.String()
	}
	return value.Interface()
}

// Bytes are shown by what they hold: certificates by subject and issuer, other
// PEM blocks by their type, anything else by its kind alone.
func shapeOf(content []byte) any {
	var held []string
	for rest := content; len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			held = append(held, "<"+strings.ToLower(block.Type)+">")
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			held = append(held, "<unreadable certificate>")
			continue
		}
		held = append(held, fmt.Sprintf("certificate %q by %q, authority %t", certificate.Subject.CommonName, certificate.Issuer.CommonName, certificate.IsCA))
	}
	if held == nil {
		return "<bytes>"
	}
	return held
}
