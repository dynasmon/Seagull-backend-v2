package fixtures

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// What a development agent found running the checks of the policy it runs on:
// a failing sshd directive, a file as it should be and a module the host does
// not have.
type Posture struct {
	AssessmentID string
	AgentID      string
	PolicyID     string
	Revision     uint64
	At           time.Time
	Results      []*assessmentv1.Result
}

func (p Posture) Assessment() *assessmentv1.Assessment {
	if p.AssessmentID == "" {
		p.AssessmentID = "asm-0000000001"
	}
	if p.AgentID == "" {
		p.AgentID = "dev-agent-01"
	}
	if p.PolicyID == "" {
		p.PolicyID = "linux-baseline"
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	if p.At.IsZero() {
		p.At = time.Now().UTC()
	}
	if p.Results == nil {
		p.Results = []*assessmentv1.Result{
			{CheckId: "ssh.root-login", Outcome: assessmentv1.Outcome_OUTCOME_FAIL, Evidence: "PermitRootLogin is yes in /etc/ssh/sshd_config"},
			{CheckId: "shadow.permissions", Outcome: assessmentv1.Outcome_OUTCOME_PASS, Evidence: "regular file, 0:42, 0640"},
			{CheckId: "cramfs.disabled", Outcome: assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE, Evidence: "the kernel has no module cramfs"},
		}
	}

	return &assessmentv1.Assessment{
		AssessmentId:   p.AssessmentID,
		SchemaVersion:  assessment.SchemaVersion,
		PolicyId:       p.PolicyID,
		PolicyRevision: p.Revision,
		AssessedAt:     timestamppb.New(p.At),
		Origin: &eventv1.Origin{
			AgentId:  p.AgentID,
			TenantId: "default",
			Host:     &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "assessment"},
		Results:    p.Results,
	}
}

func AssessmentBatch(batchID string, assessments ...*assessmentv1.Assessment) *assessmentv1.AssessmentBatch {
	return &assessmentv1.AssessmentBatch{
		BatchId:         batchID,
		ProtocolVersion: protocol.Version,
		Assessments:     assessments,
	}
}
