package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

const (
	RulesetsPath   = "/v1/rulesets"
	RulesetPath    = "/v1/rulesets/{id}"
	ValidationPath = "/v1/rulesets/validate"
	CheckPath      = "/v1/rulesets/check"
	ActivationPath = "/v1/rulesets/{id}/activate"
)

// A rule document is orders larger than anything else this listener reads, and
// a ruleset is published whole, so the ceiling is stated here rather than left
// to whatever the transport happens to allow.
const MaxDocumentBytes = 1 << 20

var ErrUnknownRuleset = errors.New("no ruleset was published under that id")

// What the control plane can do about rulesets. It owns no rule language and no
// store: compiling documents and putting a version somewhere durable both
// belong elsewhere, and an executable decides where.
type Rulesets interface {
	Validate(documents []*rulesetv1.Document) *rulesetv1.ValidationResponse
	Check(documents []*rulesetv1.Document) (*rulesetv1.ValidationResponse, *rulesetv1.CheckResponse)
	Publish(ctx context.Context, request *rulesetv1.PublishRequest, by string, at time.Time) (*rulesetv1.PublishResponse, error)
	List() *rulesetv1.VersionList
	Version(id string) (*rulesetv1.Version, bool)
	Activate(ctx context.Context, id, note, by string, at time.Time) (*rulesetv1.ActivationResponse, error)
}

func (s *Server) validateRuleset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked rulesetv1.ValidationRequest
		if !readWithin(w, r, &asked, MaxDocumentBytes) {
			return
		}
		if len(asked.GetDocuments()) == 0 {
			Refuse(w, http.StatusBadRequest, CodeNoDocuments, "validating a ruleset needs the documents it is written in")
			return
		}
		respond(w, http.StatusOK, s.rulesets.Validate(asked.GetDocuments()))
	})
}

func (s *Server) checkRuleset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked rulesetv1.CheckRequest
		if !readWithin(w, r, &asked, MaxDocumentBytes) {
			return
		}
		if len(asked.GetDocuments()) == 0 {
			Refuse(w, http.StatusBadRequest, CodeNoDocuments, "checking rules needs the documents they are written in")
			return
		}

		validation, report := s.rulesets.Check(asked.GetDocuments())
		if !validation.GetValid() {
			respond(w, http.StatusUnprocessableEntity, validation)
			return
		}
		respond(w, http.StatusOK, report)
	})
}

// A ruleset that does not compile, or whose own cases do not hold, is answered
// with what is wrong rather than refused with a code: nothing invalid is stored
// and the caller is told exactly what to fix.
func (s *Server) publishRuleset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked rulesetv1.PublishRequest
		if !readWithin(w, r, &asked, MaxDocumentBytes) {
			return
		}
		if len(asked.GetDocuments()) == 0 {
			Refuse(w, http.StatusBadRequest, CodeNoDocuments, "publishing a ruleset needs the documents it is written in")
			return
		}

		published, err := s.rulesets.Publish(r.Context(), &asked, caller.Subject, s.now())
		if err != nil {
			s.metrics.rulesetPublished("refused")
			Refuse(w, http.StatusServiceUnavailable, CodePublishFailed, err.Error())
			return
		}
		if !published.GetPublished() {
			s.metrics.rulesetPublished("invalid")
			respond(w, http.StatusUnprocessableEntity, published)
			return
		}
		s.metrics.rulesetPublished("published")
		respond(w, http.StatusCreated, published)
	})
}

func (s *Server) listRulesets() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, s.rulesets.List())
	})
}

func (s *Server) describeRuleset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version, published := s.rulesets.Version(r.PathValue("id"))
		if !published {
			Refuse(w, http.StatusNotFound, CodeUnknownRuleset, ErrUnknownRuleset.Error())
			return
		}
		respond(w, http.StatusOK, version)
	})
}

// Rolling back and rolling forward are the same act, because a version cannot
// change after it is published: activating an older id is asking for exactly
// what ran before rather than for a reconstruction of it.
func (s *Server) activateRuleset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked rulesetv1.ActivationRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		activated, err := s.rulesets.Activate(r.Context(), r.PathValue("id"), asked.GetNote(), caller.Subject, s.now())
		switch {
		case errors.Is(err, ErrUnknownRuleset):
			s.metrics.rulesetActivated("unknown")
			Refuse(w, http.StatusNotFound, CodeUnknownRuleset, err.Error())
			return
		case err != nil:
			s.metrics.rulesetActivated("refused")
			Refuse(w, http.StatusServiceUnavailable, CodeActivationFailed, err.Error())
			return
		}

		s.metrics.rulesetActivated("activated")
		respond(w, http.StatusOK, activated)
	})
}

func rulesetRoutes(s *Server) []route {
	return []route{
		{http.MethodGet, RulesetsPath, "ruleset_list", Permits(authz.Rulesets, authz.Read), s.listRulesets()},
		{http.MethodPost, ValidationPath, "ruleset_validate", Permits(authz.Rulesets, authz.Read), s.validateRuleset()},
		{http.MethodPost, CheckPath, "ruleset_check", Permits(authz.Rulesets, authz.Read), s.checkRuleset()},
		{http.MethodGet, RulesetPath, "ruleset_describe", Permits(authz.Rulesets, authz.Read), s.describeRuleset()},
		{http.MethodPost, RulesetsPath, "ruleset_publish", Permits(authz.Rulesets, authz.Write), s.publishRuleset()},
		{http.MethodPost, ActivationPath, "ruleset_activate", Permits(authz.Rulesets, authz.Write), s.activateRuleset()},
	}
}
