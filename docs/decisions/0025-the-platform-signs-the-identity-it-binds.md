# 25. The platform signs the identity it binds, and an agent renews with the certificate it is replacing

## Context

[ADR 2](0002-identity-comes-from-the-certificate.md) settled that an agent is
whoever its verified certificate says it is, and
[ADR 24](0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md)
settled that the registry can stop honouring one. Between them sits the thing
neither answers: **where the certificate comes from.**

Today it comes from `tools/devpki`, which mints the whole development estate in
one command. `internal/devpki` is classified `development` in
`tests/architecture/dependencies_test.go`, and no process that ships may name it,
so there is no issuance at all — an operator holds `agentv1.BindingRequest` and
tells the registry what some other authority signed. The contract says so out
loud: "The registry is told what was issued; it does not issue."

That leaves four things open, and BE-032 names all of them:

> Definir bootstrap e certificate issuance. Definir renewal, expiration e
> rotation. Tratar re-enrollment e perda de credenciais. Planejar CA rotation e
> coexistencia durante transicao.

It also leaves a security claim unbacked. ADR 24 answers a *revoked* agent with
the admission log and answers a *stolen key nobody has revoked* with "short
certificate lifetimes". Short lifetimes are only an answer if renewing is
cheaper than an operator visiting a machine, and nothing renews.

v1 built this and is worth reading rather than copying. `seagull/pki/signer` is a
separate HTTP service holding the agent CA, authorised by a shared bearer token,
signing a PKCS#10 request whose common name must equal the agent it is for;
`backend/app/features/agents/certs.py` records every certificate it issued;
`enrollment_replay.py` is 127 lines of AES-GCM replay protection for bootstrap
tokens. The agent side already does the right thing — `seagull-agent/internal/certrenew`
generates its own key, renews before expiry, and **persists the server CA bundle
that comes back in the renewal response.** That last line is the whole rotation
story, and it is the piece worth keeping.

## Decision

**The control plane signs agent certificates, and issuing one binds it.**

`internal/pki` is the authority: it parses a signing request, refuses one that
names another agent or carries a key below what the platform offers, and returns
both the signed certificate and the `agentv1.Identity` describing it. That
identity is the one `agent.Bindable` validates and `internal/postgres` records,
so **what was signed and what was bound cannot disagree** — the seam ADR 24 left.
The package reads no file and serves no transport; `cmd/control-api` holds the
private key, which is where a composition root belongs.

**Four decisions follow from where the two trust domains already sit.**

### The authority lives in `control-api`, not in a signer of its own

The distributed-correctness wave split the estate into an agent domain (gateway
and agents) and an operator domain (control plane, query plane and people).
`control-api` already terminates the operator domain, already decides every
request against a pinned policy, and §35 of `AGENTS.md` already places
"agents / enrollment" there.

v1's separate signer bought a real boundary because v1's backend was one process
holding the entire product. Here the boundary would be bought with a shared
bearer token between two of our own processes — authentication *weaker* than the
mutual TLS and per-request policy the control plane already applies, plus a
synchronous internal hop that §34 exists to refuse. The CA key is a mounted
secret read once at startup, and the process that reads it is the one that was
already trusted to decide who may have a certificate.

### Issuance is an operator act; renewal is not

An agent with no certificate cannot complete mutual TLS, so its first one is
asked for by somebody who can: `POST /v1/agents/{id}/certificate`, guarded by
`agents:write`, in the tenant the caller holds — the same guard registration
already passes. The platform signs and binds in one act, and a `pending` agent
becomes `active` exactly as it does today.

Renewal cannot work that way, because a renewal that needs an operator makes
short lifetimes more expensive than long ones and the acceptance criterion —
"expiração e renovação não exigem intervenção manual desnecessária" — is the
card's. So **an agent renews by presenting the certificate it is replacing**:
`control-api` gains a second listener, in the agent trust domain, serving that
one route. The subject is read off the verified chain and never from the body,
which is ADR 2 applied to a control-plane surface, and the registry is consulted
for admissibility so an agent it stopped honouring is refused a new certificate
by the same `State.Admits()` that refuses its telemetry.

A second listener is not a second process. It is one address, one trust domain
and one route, in the process §35 already names, which is the difference between
a security boundary and a microservice.

### The trust bundle travels on every issuance

`tlsx.Material` already re-reads its client authority bundle when the file
changes, and `x509.CertPool` already holds more than one authority, so the
*server* half of a certificate authority rotation works today: append the next
authority to the bundle, and both are trusted with no restart. What was missing
is the agent half.

Every issuance and every renewal carries `trust_bundle_pem` — every authority the
agent should trust, not only the one that signed it — and it is **read from the
file at the moment it is issued** rather than held from startup, so widening the
estate's trust is the same single write on both sides of the handshake. That makes
a rotation four ordered steps, each of which can be verified before the next:

1. add the next authority to the bundle every listener and every agent trusts —
   one file write, picked up on the next handshake and the next issuance;
2. wait for the estate to renew, which is what distributes the wider bundle;
3. switch the signing authority to the next one, which restarts the plane;
4. drop the previous authority from the bundle, which takes effect on the next
   handshake and leaves the connections already up to drain.

`pki.Trusts` refuses a configuration where the authority that signs is not in the
bundle it publishes, because that is the one ordering mistake that strands an
estate: agents renew onto an authority they were never told to trust.

### Bootstrap tokens are not built yet, and the reason is written down

v1's bootstrap token — hashed, expiring, use-counted, with replay protection — is
what makes enrollment practical at a thousand machines. It is also a second kind
of credential with a store, a lifecycle and an attack surface of its own, and
`Seagull-agent-v2` is empty, so nothing would use it. §32 refuses building it
before the need exists. The operator-mediated path covers the same ground for the
estate that exists, and re-enrollment and credential loss fall through it: an
agent whose key is gone is `disabled`, issued a new certificate, and made
`active` again — or, if the key is believed stolen, `revoked` and replaced by a
new identifier, which ADR 24 already made the only way back.

## What this deliberately does not do

**A superseded certificate keeps working until it expires.** Renewal replaces
which certificate the registry holds; the gateway admits by agent identifier and
does not compare fingerprints, so the certificate that was replaced still
authenticates for the rest of its validity. That is not an oversight — putting
the fingerprint on `agentv1.Admission` would make a renewal fail closed while the
compacted topic caught up, breaking ingest at the moment an agent did the right
thing.

The answers, in order of what an estate should reach for: a short validity, so
the window is bounded by configuration; and revoking the agent, which is
immediate and is what a *known* compromise deserves. If an estate ever needs
immediate rotation without revocation, the mechanism is the fingerprint on the
admission record and a roster that accepts the current one, and it should be
taken with the propagation gap solved rather than as a field added quietly.

**No certificate revocation list and no OCSP responder.** ADR 24 gave the reason
and it has not changed: the admission log answers the question a CRL answers, in
a map lookup, without a second distribution mechanism.

**The authority set is configuration, not an API.** There is no route to add or
retire a certificate authority. Three of the four steps are a single file write
that both the listener and the published bundle pick up without a restart; only
switching *which* authority signs is a restart, because that is the one step an
operator performs deliberately and once. An API over it would be a control
surface for something an estate does once a year.

## Consequences

- **`cmd/control-api` holds a private key**, which no Seagull process did before.
  It is read once at startup through the existing `_FILE` secret mechanism, never
  logged, and `.dockerignore` already keeps `.local/pki` out of the build
  context. A control plane that cannot read its authority does not serve, which
  is the fail-closed direction.
- **`control-api` gains a second listener and a second trust domain.** It is the
  first process to terminate both, and the two are separate `tls.Config`s over
  separate authorities: an operator certificate cannot renew an agent's and an
  agent certificate cannot reach `/v1/agents`.
- **The certificate trail is a fifth control-plane record.** `agent_transitions`
  says an identity was bound and not which one, so which key a machine held at a
  past moment is not answerable from it after a renewal. `agent_certificates`
  answers that, append only, superseded rather than deleted.
- **`tools/devpki` stops being the only way an agent gets an identity**, and
  keeps being how the development estate gets its authorities and its server
  certificates. The card it closes is the one that removed it from the critical
  path, not the one that removes it.
- **BE-033 is unblocked and unchanged.** The tenant still comes from the registry
  and reaches the gateway on the admission record; issuing a certificate does not
  put it in the certificate, because a tenant in a certificate is a tenant that
  cannot be corrected without reissuing one.
