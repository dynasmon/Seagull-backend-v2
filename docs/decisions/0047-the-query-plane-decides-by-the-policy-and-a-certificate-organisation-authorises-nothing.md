# 47. The query plane decides by the policy the control plane decides by, and a certificate's organisation authorises nothing

## Context

[ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md) took the tenants a
hunt may read from the organisation of the caller's certificate, until there was
an identity service to ask. [ADR 14](0014-a-token-says-who-and-the-policy-says-what.md)
then made a policy decide everything the control plane does, by the certificate's
subject, and left `hunt.Scope` reading the certificate, two paths to tenancy
that it said should be joined. [ADR 26](0026-an-agent-sends-into-the-tenant-it-was-registered-in.md)
bound the producer side and left the reader side as it was.

So a certificate with `O=acme` read acme's telemetry and detections whatever the
policy said of its subject, and removing someone from the policy did not remove
their hunting: their certificate had to expire or be revoked by an authority that
publishes no revocation list here (BE-077, P0 for the Core platform).

## Decision

**`query-api` pins the policy `control-api` decides by.** It reads the same
document, `SEAGULL_QUERY_API_POLICY`, through `internal/policyfile` at startup,
logs `policy_pinned` with its identifier as the control plane does, and holds it
in memory: the read plane still reads no relational store per request, and the
identifier in the two logs says whether both planes run on one policy.

**A hunt is authorised by the policy before its body is read.** The caller is
the common name of its verified certificate; the policy must bind that subject,
grant it `events:read` for `/v1/hunt/events` or `detections:read` for
`/v1/hunt/detections`, and the tenants of that grant are the scope the query is
compiled with. A subject the policy does not bind, or binds without the
permission, is answered `403 forbidden`; a connection with no verified
certificate `403 unscoped`. The certificate's organisation is read by nothing.

**A role removed takes effect when the query plane starts again.** That is the
declared delay until BE-078 makes the policy live on every replica; whoever
changes the policy restarts both planes, and the policy identifier each logs
says they were.

## What this deliberately does not do

**No session.** A hunt is still a request authorised by its certificate, with no
token; the control plane's sessions are its own.

**No audit of hunts.** Who asked what is logged with each answer, as before;
recording hunts as audit events is BE-039.

## Consequences

- [ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md),
  [ADR 14](0014-a-token-says-who-and-the-policy-says-what.md) and
  [ADR 26](0026-an-agent-sends-into-the-tenant-it-was-registered-in.md) are
  amended: the scope comes from the policy.
- Every deployment gives `query-api` the policy file it gives `control-api`; the
  development stack mounts `deploy/policy.yml` into both.
- A certificate issued with an organisation keeps working, and its organisation
  means nothing; callers are bound by subject in the policy, as operators already
  are.
