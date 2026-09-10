package control

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const RenewalPath = "/v1/agents/certificate"

// The agent-facing half of the control plane, and the only route on it. It
// terminates the agent trust domain rather than the operator one, so a
// certificate that may renew cannot reach /v1/agents and an operator certificate
// cannot renew an agent's.
func NewRenewalServer(options ServerOptions) (*httpx.Server, error) {
	if options.RenewalTLS == nil {
		return nil, errors.New("the renewal listener authenticates an agent by certificate and cannot serve without one")
	}
	handler, err := NewRenewalHandler(options)
	if err != nil {
		return nil, err
	}

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "control-api-renewal",
		Address:           options.RenewalAddress,
		Handler:           handler,
		TLS:               options.RenewalTLS,
		Logger:            options.Logger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
		ShutdownTimeout:   options.ShutdownTimeout,
		MaxHeaderBytes:    16 << 10,
	})
}

func NewRenewalHandler(options ServerOptions) (http.Handler, error) {
	server, err := newServer(options)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle(http.MethodPost+" "+RenewalPath,
		options.Instrumentation.Handle("agent_certificate_renew", server.renewCertificate()))
	return mux, nil
}

// The subject is read off the verified chain and never from the body: an agent
// that could name itself could renew somebody else's identity, which is ADR 2
// applied to a control-plane surface.
func (s *Server) renewCertificate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, err := agentidentity.FromConnection(r.TLS)
		if err != nil {
			s.metrics.certificateRenewed("unidentified")
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
			return
		}
		if s.renewals != nil && !s.renewals.Allow(presented.AgentID) {
			s.metrics.certificateRenewed("rate_limited")
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this agent is renewing too often")
			return
		}

		var asked agentv1.RenewalRequest
		if !readWithin(w, r, &asked, MaxCertificateBodyBytes) {
			return
		}

		signed, err := s.authority.Sign(presented.AgentID, asked.GetCsrPem(), s.certificateLife, s.now())
		if err != nil {
			s.metrics.certificateRenewed("refused")
			s.refuseSigning(w, err)
			return
		}
		issued, err := s.issued(signed)
		if err != nil {
			s.metrics.certificateRenewed("refused")
			s.unavailable(w, CodeSigningRefused, err)
			return
		}

		if _, err := s.agents.Renew(r.Context(), presented.AgentID, agent.Move{
			Identity:  signed.Identity,
			Actor:     presented.AgentID,
			At:        s.now(),
			Authority: s.authority.Subject(),
		}); err != nil {
			s.metrics.certificateRenewed("refused")
			s.refuseAgent(w, err)
			return
		}
		s.metrics.certificateRenewed("renewed")
		s.logger.Info("agent_certificate_renewed",
			slog.String("agent_id", presented.AgentID),
			slog.String("serial", signed.Identity.GetSerial()),
			slog.String("authority", s.authority.Subject()))

		respond(w, http.StatusCreated, issued)
	})
}
