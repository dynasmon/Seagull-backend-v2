# 51. The rules an installation starts from are its first publication, and the pointer is the installation's until a person moves it

## Context

[ADR 15](0015-a-ruleset-is-published-to-a-log.md) made the engine's rule tree
its bootstrap: the engine runs the tree until the log names something to run,
and the log wins from then on. The tree itself was never in the log. An engine
therefore detected on rules the catalogue had never read, and the rule that
keeps a revision meaning one thing had nothing to hold an installation's first
publication against.

The integration audit of 2026-11-09 did exactly that. On an installation whose
engine had been detecting from the shipped tree, the first publication carried
`ssh.failed_password_from_outside` at revision 1 with another severity and was
answered `201`; the shipped rule, published afterwards, was refused `422` as
`already published at revision 1 asking something else`. Stored detections then
held two meanings under one rule and revision, and the ruleset the engine said
it had pinned was listed nowhere.

Two answers were weighed. Holding a publication to the ruleset in force as well
as to the log keeps the tree out of the log and makes two sources for one fact:
what a revision means would be read from the catalogue or from a disk, depending
on which process asked and when. The other is that the tree is published, so the
catalogue stays the only place the question is asked.

## Decision

**The rules an installation starts from are published by `control-api` before
anything else can be.** At every start, after it has read the log whole and
before its listener opens, `control-api` reads the rule tree it is given — the
tree the engine starts on, through the reader the engine uses, so both compose
one identifier ([ADR 8](0008-a-ruleset-is-named-by-what-is-in-it.md)) — and
publishes it as a version when the log does not hold it. `control-api` remains
the only writer of `security.rulesets`: the engine publishes nothing, and no
step of the installation writes the log beside it, so an operator runs nothing
for this to happen.

**They are published under the installation's name.** `published_by` and
`activated_by` read `the installation`, which is not a subject: the access
policy cannot bind it and the guard refuses a certificate that carries it, so a
line of the trail reading it was written by no person.

**The pointer is the installation's until a person moves it.** A start activates
its tree when nothing is active, and when what is active is another ruleset the
installation itself activated — an upgrade whose tree changed. Once a person
has activated anything, the shipped rules included, a start publishes its tree
and leaves the pointer where it is. An upgrade brings the rules of a release
and never replaces a ruleset somebody chose.

**The same rules published again are not written again.** The log keeps the
last record under a key, and a version is keyed by what is in it, so a second
record would, once the topic is compacted, replace who published the rules
first — the installation included. A publication of rules the catalogue already
holds is answered as published, under the same identifier, and writes nothing.

**The bootstrap stands.** An engine that cannot reach a control plane still
detects from its tree. On a fresh installation the tree and the first
publication are one ruleset under one identifier, so an engine reading the log
for the first time keeps the snapshot it started on: nothing is swapped, and
nothing its counting rules remember is rebuilt under another ruleset.

**The tree of a release is publishable over every tree shipped before it.**
Each shipped tree is kept as the record a fresh installation wrote for it, in
`cmd/control-api/testdata/starting`, named by its identifier — which is what an
installation of that release holds in its log.
`TestTheShippedRulesArePublishableOverEveryTreeShippedBefore` reads all of them
into one catalogue and requires the tree of this build to be admitted beside
them and to be one of them; `make record-starting-rules` writes the one that is
missing. A shipped rule that changed and kept its revision fails the build, and
the recording is refused. One that changed under its next revision is a pull
request that adds a recording. The same run holds a build to reading the
records the releases before it wrote.

**What cannot be recorded is said.** A tree that cannot be read, does not
compile, contradicts its own cases or encodes to more than the topic carries
keeps `control-api` from starting: the engine would be running what the log
could not record. A tree holding no rules publishes nothing and is logged as
`starting_ruleset_empty`, because an empty ruleset that was activated would be
followed by every engine. A tree the log contradicts — a person took the next
revision of a shipped rule before a release did — is logged at error level as
`starting_ruleset_refused` with the rule and the revision; nothing is written,
the pointer stays, and the control plane serves. The catalogue keeps what was
asked first, and the engine keeps running what the pointer names.

## What this deliberately does not do

**It does not rewrite what was stored.** Detections made before this decision
keep the meaning they were made with. An installation whose log already holds a
shipped revision under another meaning is told so at every start and is not
repaired.

**It does not order a start against an activation.** A start decides from the
log it replayed and then writes. A person activating a ruleset on another
replica between the two is ordered by the log like any two activations: the
later write is the pointer. The window is one start, it opens only when an
upgrade brings a changed tree to an installation still on shipped rules, and
both activations are on the trail. Closing it wants a reader that refuses the
installation's activation after a person's and a writer that puts the person's
back, which is two rules for a key compaction keeps one record of.

**It does not make the two trees one by construction.** A deployment gives the
engine and the control plane the same tree. Compose is held to it by
`TestTheEngineAndTheControlPlaneAreGivenOneRuleTree`, and the chart (BE-086)
mounts one. Given two, an installation would record one ruleset and detect from
the other until its engine read the log.

## Consequences

- On a fresh installation a publication that changes a shipped rule at its
  revision is refused `422`, naming the rule and the revision. The shipped rules
  are listed as a version `the installation` published, and the ruleset the
  engine says it pinned is the one listed as active.
- `control-api` reads `SEAGULL_DETECTION_RULES`, the variable the engine reads,
  and does not start without the tree.
- What a start did is logged: `starting_ruleset_published`,
  `starting_ruleset_activated`, or one of the two refusals above. A start that
  found everything in place logs nothing.
- A start that ended between the publication and the activation is finished by
  the next. Two replicas starting together on a fresh installation both write:
  one version under one key, two lines of the trail, one pointer.
- Changing a shipped rule is a new revision and a new recording, both in the
  pull request. A recording is never removed.
- BE-073 and BE-084 rest on this: what an engine ran is what the catalogue
  holds.
