package control

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
)

const DescriptorPath = "/v1/descriptor"

type ServerOptions struct {
	Address         string
	TLS             *tls.Config
	Guard           *Guard
	Sessions        *Sessions
	Registry        *Registry
	Rulesets        Rulesets
	Metrics         *Metrics
	Instrumentation *httpx.Instrumentation
	Logger          *slog.Logger
	Now             func() time.Time
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

type Server struct {
	sessions *Sessions
	registry *Registry
	rulesets Rulesets
	metrics  *Metrics
	now      func() time.Time
}

type route struct {
	method      string
	path        string
	name        string
	requirement Requirement
	handler     http.Handler
}

func NewServer(options ServerOptions) (*httpx.Server, error) {
	if options.TLS == nil {
		return nil, errors.New("the control listener authenticates a caller by certificate and cannot serve without one")
	}
	handler, err := NewHandler(options)
	if err != nil {
		return nil, err
	}

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "control-api",
		Address:           options.Address,
		Handler:           handler,
		TLS:               options.TLS,
		Logger:            options.Logger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
		ShutdownTimeout:   options.ShutdownTimeout,
		MaxHeaderBytes:    16 << 10,
	})
}

func NewHandler(options ServerOptions) (http.Handler, error) {
	switch {
	case options.Guard == nil:
		return nil, errors.New("the control listener serves nothing without a guard")
	case options.Sessions == nil:
		return nil, errors.New("the control listener needs a session store")
	case options.Registry == nil:
		return nil, errors.New("the control listener needs a policy")
	case options.Rulesets == nil:
		return nil, errors.New("the control listener administers rulesets and needs somewhere to keep them")
	case options.Metrics == nil:
		return nil, errors.New("the control listener needs metrics")
	case options.Instrumentation == nil:
		return nil, errors.New("the control listener shares the process http instrumentation")
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	server := &Server{
		sessions: options.Sessions,
		registry: options.Registry,
		rulesets: options.Rulesets,
		metrics:  options.Metrics,
		now:      options.Now,
	}

	mux := http.NewServeMux()
	for _, entry := range server.routes() {
		if !entry.requirement.valid() {
			return nil, fmt.Errorf("route %s %s does not say what it requires", entry.method, entry.path)
		}
		guarded := options.Guard.Handle(entry.name, entry.requirement, entry.handler)
		mux.Handle(entry.method+" "+entry.path, options.Instrumentation.Handle(entry.name, guarded))
	}
	return mux, nil
}

// Every route names what it requires here, and NewServer refuses one that does
// not: an endpoint nobody decided about cannot reach the mux.
func (s *Server) routes() []route {
	return append([]route{
		{http.MethodGet, DescriptorPath, "descriptor", Certificate(), s.descriptor()},
		{http.MethodPost, SessionPath, "session_open", Certificate(), s.openSession()},
		{http.MethodGet, SessionPath, "session_describe", Session(), s.describeSession()},
		{http.MethodDelete, SessionPath, "session_revoke", Session(), s.revokeSession()},
		{http.MethodGet, SessionsPath, "session_list", Session(), s.listSessions()},
	}, rulesetRoutes(s)...)
}

func (s *Server) descriptor() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		encoded, err := proto.Marshal(protocol.Descriptor(s.now()))
		if err != nil {
			Refuse(w, http.StatusInternalServerError, "response_encoding_failed", "the answer could not be encoded")
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(encoded)
	})
}
