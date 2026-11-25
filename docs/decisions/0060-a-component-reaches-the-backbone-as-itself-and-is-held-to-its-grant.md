# 60. A component reaches the backbone as itself and is held to its grant: its principal and its group are its name, the migrator grants it what the manifest names and refuses to finish while it holds more, and production is reached only over TLS by processes that authenticate

## Context

The security audit of 2026-09-26 made the backbone's transport secure by default
(SEC-04): TLS on unless a deployment turns it off, a mechanism a deployment has to
name, and a password refused on a plaintext connection.
[ADR 41](0041-production-is-the-default-and-development-is-declared.md) then made
production the default and development a declaration, and said in so many words
that it did not grant per-component principals. What the audit left open, SEC-09,
is that authenticating a connection limits nothing it may do: no component has a
principal of its own and the backbone holds no ACL, so any client that reaches the
brokers may write `security.agents` (which decides an agent's tenant),
`security.advisories` (which decides what is vulnerable), `security.detections` and
`security.rulesets`. The threat models of the agents and the advisories rank it the
highest residual. BE-003 and BE-006 left a registry of consumer groups for the day
groups became something to authorise; a group is created by the broker on demand,
and two processes sharing one silently read half a stream each.

Since 2026-11-10 the installation makes and applies what a person would otherwise
repeat (invariant 18): nobody creates a broker user by hand.

Probing Redpanda v26.2.7, the release the stack runs, settled what the broker
offers: SCRAM users and ACLs are both made over the Kafka API
(`AlterUserScramCredentials`, `CreateAcls`), so the migrator needs no broker-specific
interface; an idempotent producer needs only WRITE on its topic, not
IDEMPOTENT_WRITE on the cluster; a group, a topic's configuration and another
group's committed offsets are refused without their own ACL; and a wrong password
reaches a ping as `SASL_AUTHENTICATION_FAILED` while a produce retries it until its
deadline, as a generic timeout.

Nathan decided on 2026-11-25, on three recommendations: a component's group is its
name and the settings that renamed one go; a component's principal is its name and
the migrator reads every component's password from one directory holding a file
per component; and outside a declared development backbone a process refuses one
reached without TLS or without authentication.

## Decision

**The grants are a manifest in code.** `broker.Topology.Grants` names, for each of
the fifteen components that reach the backbone, what it writes, what it consumes in
its own group, what it follows whole with no group (a state log: the roster, the
rulesets, the advisories' backlog, everything the fleet judge reads), and whose
committed positions it observes (the vulnerability matcher, the three owners it
waits on). A grant's permissions follow from it and from nothing else:

| What the manifest says | What the broker holds |
|---|---|
| writes a topic | WRITE, DESCRIBE, DESCRIBE_CONFIGS on it |
| consumes or follows a topic | READ, DESCRIBE, DESCRIBE_CONFIGS on it |
| consumes in its group | READ and DESCRIBE on the group named after it |
| observes a component | DESCRIBE on that component's group |

Every topic a process touches has its configuration read because every process
verifies its topics before it serves. Nothing administrative is granted to a
component: no CREATE, ALTER, DELETE, ALTER_CONFIGS, nothing on the cluster.
Tests hold the manifest to the platform: every topic is written by a component;
`security.agents` and `security.rulesets` by `control-api` alone and
`security.advisories` by `advisory-importer` alone; no component writes what it
consumes in its group (the three that read their own log back read it whole, as
owners); a group is read only by the component named after it and only described
by the one that observes it. An architecture test holds it to the tree: every
component the Makefile builds that imports the broker is granted, `backbone-migrator`
is granted nothing, each declares the service name it is granted under, and each
observes what the backbone refuses it before it builds a client.

**A component's principal and its consumer group are its name.** The thirteen
`SEAGULL_*_CONSUMER_GROUP` settings and the matcher's three `*_OWNER` settings are
gone: two processes cannot share a group, because the broker refuses one a group not
named after it, and the groups the matcher waits on are the manifest's. A replay is
a group's offsets moved, which is the broker's operation, not a group renamed. A
process authenticates as its own name unless `SEAGULL_BACKBONE_SASL_USER` says
otherwise, which only the migrator needs.

**`backbone-migrator` gives every component its credential and exactly its grant.**
On a backbone that authenticates by SCRAM it reads one password per component from
`SEAGULL_BACKBONE_PRINCIPALS_DIR`, a directory holding a file named after each
component — the shape of a Kubernetes Secret mounted as a volume, read through an
`os.Root` and only for the files of the components granted. It sets each
component's SCRAM credential under the deployment's mechanism, then converges the
ACLs of the fifteen principals: what is missing is granted, and whatever else a
component's principal holds is revoked, whoever added it. A principal that is not a
component's is never touched. A backbone that authenticates and a migrator given no
directory is a refused configuration; under `none` it applies nothing and says so.
The migrator authenticates as the backbone's superuser, which the deployment
bootstraps (`backbone-migrator` in the reference) and which is the only principal
that may make users and ACLs.

**The migrator refuses to finish while a component holds more than its grant.**
A broker that keeps ACLs and enforces none, an ACL granted to every principal, or a
component made a superuser each give a component more than its grant, and none of
them is an ACL of the component's own, so converging cannot see it. After
converging, the migrator asks as every component and fails while one can see a
topic, read a topic's configuration or describe a group its grant does not name.
Seeing covers every operation that implies DESCRIBE; the other two cover what does
not.

**Production is reached over TLS by processes that each authenticate.** This
amends ADR 41: outside a declared `SEAGULL_BACKBONE_DURABILITY=development`, a
process refuses `SEAGULL_BACKBONE_TLS=false` and refuses
`SEAGULL_BACKBONE_SASL_MECHANISM=none`, naming the setting and the declaration that
admits it. A client certificate alone is not authentication here: one certificate
given to every process makes them one principal, and the grants would mean nothing.
It is refused where the deployment's settings are read, so a `Security` built in
code, as the integration suite builds one, is not.

**A refusal is named and counted, never a generic backbone error.** A refused
credential is `broker.ErrNotAuthenticated` and a refused operation
`broker.ErrNotAuthorized`, wrapping the broker's answer, wherever a process meets
one: a ping, the verification of its topics, a state log's read, a position it
observes. Every client a process builds carries the process's `broker.Denials`,
which counts `seagull_backbone_denials_total{reason}` — `authentication` or
`authorization` — from the connections, group sessions, produced records and fetches
the backbone refused, and backs the readiness check `backbone-access`: not ready
while new refusals arrive since readiness last looked, named by the newest, and
ready again once a look finds none, so one refusal costs one probe and a refusal
that persists keeps the process out of service. The readiness check `backbone`
names a refused credential.

**Every client states its limits.** `Security` gives every client a 10 second dial
timeout, 10 seconds of request overhead, a 20 second idle timeout and a 100 MiB
ceiling on what one response may make it read, instead of inheriting them.

**It is proven against a backbone run as production runs one.** `make
test-integration` starts `redpanda-secured` (`deploy/compose.test.yaml`, the image
the stack runs, held equal by a test): one TLS listener on which every client
authenticates by SCRAM, authorization on, and a superuser bootstrapped from a
password the Makefile generates under `.local/` and never into the repository. The
broker mints its own authority when it starts and discards the key, so no key exists
outside it; the suite trusts the certificate it exports. Against it, with the real
migrator: every component writes every topic it is granted and is refused every
other (300 writes), consumes in its own group and is refused another's, a write
added beyond a grant is revoked on the next run while an operator's own permission
survives, a grant to every principal of seeing a topic, reading its configuration or
joining a group is refused, refusals reach readiness named and are counted, and an
anonymous or plaintext client is refused. Thirty-one injected defects were each
caught.

## What this deliberately does not do

**It does not sign records.** SEC-09 named producer signatures as the fallback for
a broker that cannot authorise per producer; this one can.

**It does not decide the broker's listeners.** That production runs no anonymous or
plaintext listener is the deployment's to install (BE-086, whose install test holds
it). What this makes true is that no process speaks to one in production and that an
installation whose broker holds a component to less than its grant does not finish
installing.

**It does not issue per-component certificates**, so a certificate is never a
component's principal.

**It does not rotate credentials on its own.** A changed password file is set on
the migrator's next run, and a process picks it up when it restarts; until then a
process holding the old one keeps the connections it has and is refused new ones,
by name.

**It does not remove a principal the manifest stops naming.** A component a later
release drops keeps its user and its ACLs until an operator removes them, because
the migrator cannot tell a principal the platform made from one an operator made.

## Consequences

- A deployment whose backbone authenticates gives the migrator the principals
  directory and every process its own password file; each run sets every credential
  again, because a password cannot be read back to compare, and reports it.
- A deployment that renamed a group loses the setting; no production deployment
  exists, and the stack's own Compose file never set one.
- A production deployment can no longer run against an anonymous or plaintext
  backbone; the development Compose file already declares `development`.
- The integration job starts a second broker and runs about two minutes longer.
- [ADR 41](0041-production-is-the-default-and-development-is-declared.md) is amended
  as above.
