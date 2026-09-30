package agent

import (
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// What was bound, written down as its own record. The registry row carries only
// the certificate that is current, so without this a renewal would leave no
// answer to which key a machine held before it.
func Certificate(moved *agentv1.Agent, move Move) *agentv1.CertificateRecord {
	if move.Identity == nil {
		return nil
	}
	return &agentv1.CertificateRecord{
		AgentId:          moved.GetAgentId(),
		Identity:         moved.GetIdentity(),
		AuthoritySubject: move.Authority,
		IssuedBy:         move.Actor,
	}
}

// What a binding answered, kept with the certificate it bound so that the one
// renewal that asked for it can be told from anybody else presenting the
// certificate it replaced.
func Answering(move Move) Asked {
	if !move.Renewal {
		return Asked{}
	}
	return Asked{Presented: move.PresentedFingerprint, Request: move.Request}
}
