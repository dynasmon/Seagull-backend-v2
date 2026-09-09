package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const supersedeCertificate = `UPDATE agent_certificates SET superseded_at = $2
WHERE agent_id = $1 AND superseded_at IS NULL`

const insertCertificate = `INSERT INTO agent_certificates
	(fingerprint, agent_id, serial, subject, authority_subject, issued_by, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`

const certificateColumns = `agent_id, subject, serial, fingerprint,
	issued_at, expires_at, authority_subject, issued_by, superseded_at`

// Newest first, and unscoped by design: the agent is read first, within the
// tenants the caller holds, so a trail is never reached without a scope.
func (a *Agents) Certificates(ctx context.Context, id string, tenants []string) (*agentv1.CertificateHistory, error) {
	if _, err := a.Agent(ctx, id, tenants); err != nil {
		return nil, err
	}

	rows, err := a.store.pool.Query(ctx,
		"SELECT "+certificateColumns+" FROM agent_certificates WHERE agent_id = $1 ORDER BY issued_at DESC", id)
	if err != nil {
		return nil, fmt.Errorf("read the certificates of agent %s: %w", id, err)
	}
	signed, err := pgx.CollectRows(rows, restoreCertificate)
	if err != nil {
		return nil, fmt.Errorf("read the certificates of agent %s: %w", id, err)
	}
	return &agentv1.CertificateHistory{AgentId: id, Certificates: signed}, nil
}

func recordCertificate(ctx context.Context, transaction pgx.Tx, one *agentv1.CertificateRecord, at time.Time) error {
	if _, err := transaction.Exec(ctx, supersedeCertificate, one.GetAgentId(), at.UTC()); err != nil {
		return fmt.Errorf("supersede the certificate of agent %s: %w", one.GetAgentId(), err)
	}
	identity := one.GetIdentity()
	if _, err := transaction.Exec(ctx, insertCertificate,
		identity.GetFingerprintSha256(), one.GetAgentId(), identity.GetSerial(), identity.GetSubject(),
		one.GetAuthoritySubject(), one.GetIssuedBy(),
		identity.GetIssuedAt().AsTime(), identity.GetExpiresAt().AsTime(),
	); err != nil {
		if duplicate(err) {
			return fmt.Errorf("%w: that certificate was already recorded", agent.ErrMalformedIdentity)
		}
		return fmt.Errorf("record the certificate of agent %s: %w", one.GetAgentId(), err)
	}
	return nil
}

func restoreCertificate(row pgx.CollectableRow) (*agentv1.CertificateRecord, error) {
	var (
		record              agentv1.CertificateRecord
		identity            agentv1.Identity
		issuedAt, expiresAt time.Time
		supersededAt        *time.Time
	)
	if err := row.Scan(
		&record.AgentId, &identity.Subject, &identity.Serial, &identity.FingerprintSha256,
		&issuedAt, &expiresAt, &record.AuthoritySubject, &record.IssuedBy, &supersededAt,
	); err != nil {
		return nil, err
	}

	identity.IssuedAt = timestamppb.New(issuedAt.UTC())
	identity.ExpiresAt = timestamppb.New(expiresAt.UTC())
	record.Identity = &identity
	record.SupersededAt = instant(supersededAt)
	return &record, nil
}
