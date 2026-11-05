# 48. Every answer an agent reads is recorded here, and changes only by a version decision

## Context

The agent claims compatibility only with the backend commits it recorded
itself: its sessions copied this repository, added throwaway tests driving the
end-to-end harness, and kept the exchanges in its own `tests/compatibility`.
Nothing here published which agent releases a platform serves, and nothing here
failed when an answer an agent reads changed: `BE-045` turned a `503` into a
`422` and the agent learned it by recording again. The agent's Core gate needs
every supported pairing evidenced (BE-056), and §6.6 of the backlog promises a
compatibility window this repository never stated.

## Decision

**A platform serves the newest agent release and the one before it.** It
accepts the protocol and schema versions both speak, and a change that a
deployed agent inside that window would read differently takes a new protocol
or schema version, which the descriptor ([ADR 45](0045-a-listener-tells-an-agent-what-it-serves-and-decides-nothing-by-it.md))
then lists beside the old. Within a protocol version a refusal keeps its code,
its status and what it says of the record: an agent reads a code it knows as
what it meant when it was recorded.

**This repository records every answer an agent reads.**
`TestTheAnswersAnAgentReadsAreTheOnesRecorded` drives the real listeners — the
gateway and the control plane's agent listener, over mutual TLS — through each
stream's acknowledgement and every refusal it gives, both descriptors and their
`304`, issuance, renewal (the same request asked again after a lost answer
included), the policy and the update an agent is handed, and keeps each request
and answer in `tests/e2e/testdata/agent/protocol-1`, with `answers.json` naming
each, its route, status, headers and a summary of what the reply says.
`make record-agent-answers` writes it.

**A changed answer fails the build until it is recorded again on purpose.**
Every run compares the summary of each answer with the one recorded, and a
difference, a scenario gone or a scenario new fails with what changed. Recording
again is the decision: the pull request shows the diff of `answers.json`, and a
change to an answer an agent inside the window reads is a version decision made
there, not a fixture refreshed. The recording also names the protocol and the
contracts release `go.mod` requires, so moving either records again.

**A summary keeps what an agent may depend on.** Codes, fields, indexes,
counts, routes, schema ranges, limits and certificate subjects are kept; what a
recording cannot repeat — instants, serials, key identifiers, signatures,
digests and the prose of a refusal's detail — is replaced by its shape.

**The agent takes its evidence from a release of this repository alone.** It
copies `tests/e2e/testdata/agent/protocol-<N>` from the tree of a tag or a
commit and reads the answers with its own code; nothing of this repository is
imported or run.

## What this deliberately does not do

**No release artifact.** The recordings are files in the tree; publishing them
with a release is BE-043's.

**Answers the harness cannot reach are not recorded:** a request without a
client certificate ends at the handshake, and the agent listener of the
end-to-end plane always hands out updates, so `agent_updates_not_configured` is
held by the control plane's own tests.

## Consequences

- An answer that changes meaning without a new version is a pull request that
  shows the change in `answers.json`; one that changes by accident is a red build.
- The agent's compatibility suite reads these recordings (AG-003, AG-039) in
  place of exchanges recorded from copies of this repository.
- A new route or refusal an agent reads is added to the recorder with it.
