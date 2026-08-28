# 14. A token says who, and the policy says what

## Context

[ADR 2](0002-identity-comes-from-the-certificate.md) settled how the platform
learns who is calling: the common name of a verified client certificate, with no
header and no fallback. [ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md)
built the read plane on top of it, taking the tenants a caller may read from the
certificate's organisation and noting that when there is an identity service to
ask, the scope would come from there instead.

BE-028 is that service, and it arrives with a problem the certificate cannot
solve. A certificate is issued for months and revocation is not checked anywhere
in this stack — a carried-over lesson from v1, where short lifetimes were also
the only answer. Authorisation, meanwhile, changes on the timescale of somebody
joining a team or leaving one. Binding what a person may do to a credential
nobody can withdraw means every change waits for an expiry.

v1's answer was worse in a different direction. Roles were free strings compared
at the point of use, so the only way to learn what a role allowed was to grep for
it, and a misspelled role granted nothing while reading in the configuration as
though it granted something. Administrative operations were kept out of reach by
not drawing the button.

## Decision

Three separate things, decided in three separate places.

**Authentication is the certificate.** The control plane terminates mutual TLS
itself and takes the subject from the verified leaf, exactly as the gateway and
the query plane do. Nothing else is consulted and there is no plaintext mode.

**A session is a revocable stand-in for that certificate.** `POST
/v1/auth/session` exchanges a completed handshake for a short-lived token bound
to a fingerprint of the certificate that asked for it. The token is spendable
only on a connection that proves the same private key, so lifting one off a log
or a proxy buys nothing. Sessions are held as an allowlist rather than a
revocation list: a token works while its session is live, so ending one takes
effect at the next request, and nothing survives a restart.

**Authorisation is the policy, resolved per request.** The token carries identity
and no authority at all. On every request the guard resolves what the subject may
do from the policy the process is currently holding. A role taken away is gone at
the next request rather than at the next expiry.

A permission is a typed resource and a typed verb, never a string. Both sets are
closed, and an undeclared one is refused when the policy document is read — at
startup, which is the only moment somebody is looking. A binding carries roles
and tenants, both required, and an empty list is never a wildcard.

Every route declares what it requires, and `Requirement` has no value meaning
"anybody": the zero value refuses, and `NewHandler` will not register a route
that does not say. Deny-by-default is therefore a property of how routes are
declared rather than a check somebody has to remember to write.

## Consequences

- What a caller may do can be changed without reissuing anything, and takes
  effect at their next request.
- A stolen token is useless, so the token can be carried by a client that cannot
  hold a private key safely, as long as the connection can.
- The grant is sent to the client so a user interface can show somebody what they
  hold. It is a courtesy: the server decides every request against its own policy
  regardless of what the client believes, so hiding a control is never what stops
  it being used.
- Sessions live in memory. A restart signs everybody out, and a second replica
  does not honour the first's tokens. Both are acceptable while the control plane
  is one process; a shared session store is the change that removes them.
- The policy is a document read at startup and reloadable. BE-029 makes it
  mutable through an API, and the registry it is pinned to already swaps
  atomically for that reason.
- `hunt.Scope` still derives its tenants from the certificate. The query plane
  and the control plane therefore read tenancy from the same place but by two
  paths, and joining them is the change BE-029 or BE-030 should make rather than
  the one that introduces the model.
- Revocation of certificates is still not checked. A session can now be ended
  without one, which narrows the gap without closing it; BE-032 owns the rest.
