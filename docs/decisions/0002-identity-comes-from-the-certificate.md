# 2. Agent identity comes from the certificate

## Context

v1 terminates mutual TLS at the edge proxy and forwards the certificate common
name to the backend in `X-Agent-Cert-CN`. Whether the backend enforces that the
header matches the claimed agent is decided by
`SEAGULL_AGENT_MTLS_IDENTITY_BINDING`, which defaults to `warn`.

Two things follow. Any process that can reach the backend can claim to be any
agent, and the safe behaviour is opt-in.

Separately, v1 authenticates agents with a credential stored in PostgreSQL,
which means a write to a hot row on every request and a use counter that ran
itself out in normal operation.

## Decision

The gateway terminates mutual TLS itself. The agent identity is the common name
of the leaf certificate in the verified chain, and nothing else is consulted.
There is no header, no mode and no fallback.

The gateway overwrites `origin.agent_id` and `origin.tenant_id` on every event
before validating it. What a producer wrote in those fields is discarded, not
merged.

## Consequences

- Impersonation requires a certificate the authority issued, which is the
  property the PKI already provides.
- The gateway authenticates without touching a database, so the contention and
  the exhausting counter are both gone.
- The identity in an event is the identity that opened the connection, which is
  what an investigation needs to be able to trust.
- Tenancy is currently a gateway-wide setting rather than a certificate claim.
  The field exists in the contract and travels the whole pipeline, so binding it
  to the certificate later changes one function.
- Revocation is not checked. Short certificate lifetimes and re-enrollment are
  the current answer, as in v1.
