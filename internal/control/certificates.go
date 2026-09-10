package control

import (
	"errors"
	"net/http"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	AgentCertificatePath  = "/v1/agents/{id}/certificate"
	AgentCertificatesPath = "/v1/agents/{id}/certificates"

	MaxCertificateBodyBytes = 32 << 10
)

// Signing and binding are one act. The registry is told what this process just
// put its name to, so what was issued and what the platform expects an agent to
// present cannot drift apart.
func (s *Server) issueCertificate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked agentv1.CertificateRequest
		if !readWithin(w, r, &asked, MaxCertificateBodyBytes) {
			return
		}

		id := r.PathValue("id")
		signed, err := s.authority.Sign(id, asked.GetCsrPem(), s.certificateLife, s.now())
		if err != nil {
			s.refuseSigning(w, err)
			return
		}
		issued, err := s.issued(signed)
		if err != nil {
			s.metrics.certificateIssued("refused")
			s.unavailable(w, CodeSigningRefused, err)
			return
		}

		bound, err := s.agents.Move(r.Context(), id, caller.Grant.Tenants(), agent.Move{
			Identity:  signed.Identity,
			Note:      asked.GetNote(),
			Actor:     caller.Subject,
			At:        s.now(),
			Expected:  asked.GetExpectedRevision(),
			Authority: s.authority.Subject(),
		})
		if err != nil {
			s.metrics.certificateIssued("refused")
			s.refuseAgent(w, err)
			return
		}
		s.metrics.certificateIssued(agentState(bound))

		respond(w, http.StatusCreated, issued)
	})
}

func (s *Server) agentCertificates() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		trail, err := s.agents.Certificates(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAgent(w, err)
			return
		}
		respond(w, http.StatusOK, trail)
	})
}

// The bundle is read here rather than held from startup, and travels with every
// certificate rather than only when it changes: that is what lets an authority be
// added to the estate's trust without restarting the plane that publishes it, and
// it is the half of a rotation nobody can perform by hand.
func (s *Server) issued(signed pki.Issued) (*agentv1.IssuedCertificate, error) {
	bundle, err := s.trustBundle()
	if err != nil {
		return nil, err
	}
	if err := pki.Trusts(bundle, s.authority); err != nil {
		return nil, err
	}
	return &agentv1.IssuedCertificate{
		CertificatePem: signed.CertificatePEM,
		ChainPem:       s.authority.Chain(),
		TrustBundlePem: bundle,
		Identity:       signed.Identity,
	}, nil
}

func (s *Server) refuseSigning(w http.ResponseWriter, err error) {
	if errors.Is(err, pki.ErrMalformedRequest) {
		Refuse(w, http.StatusUnprocessableEntity, CodeMalformedRequest, err.Error())
		return
	}
	s.unavailable(w, CodeSigningRefused, err)
}

func certificateRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, AgentCertificatePath, "agent_certificate_issue",
			Permits(authz.Agents, authz.Write), s.issueCertificate()},
		{http.MethodGet, AgentCertificatesPath, "agent_certificate_history",
			Permits(authz.Agents, authz.Read), s.agentCertificates()},
	}
}
