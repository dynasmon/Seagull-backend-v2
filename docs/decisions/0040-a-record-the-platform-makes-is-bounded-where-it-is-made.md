# 40. What the platform makes is bounded where it is made: a rule by the heaviest detection it could make, a ruleset by the log it is published to

## Context

[ADR 37](0037-a-record-is-bounded-by-what-its-topic-carries.md) made every topic
declare the largest batch it carries and bounded every record the gateway admits.
It left what the platform makes itself to BE-094, naming two producers that
write records nothing weighs where they are made:

- `analysis-engine` makes a detection whose evidence is one entry per question
  the rule asked, and a rule's questions are bounded only by its document. The
  writers refuse a detection above `detection.MaxDetectionBytes` (256 KiB) —
  `detection-writer` quarantines it and `alert-writer` sets it aside — and above
  what `security.detections` carries the engine's publish is refused, retried
  forever, and its partition stops.
- `control-api` reads a ruleset's documents within 1 MiB, but an alias in a
  document repeats the node it names: a 285,555-byte document holding one list
  of 4,000 accounts and four aliases of it is a ruleset record of 1,280,940
  bytes. Its publication was answered `503 ruleset_not_published`, although it
  could never succeed.

Auditing what a detection carries found that a rule is not the only thing that
weighs on it. Four ways let an agent — any registered one, with any rule, the
shipped ones included — make the detection of its own event one its consumers
refuse, so that an attacker's failed password raises no alert:

- **The origin and the instant were copied whole.** A decoder keeps the fields
  it does not know and the gateway keeps them, deliberately (ADR 37), so an event
  of 307,518 bytes that every bound admits, its origin carrying 300 KiB of
  undeclared fields, made a detection of 307,471 bytes. The event time was shared
  with the event, its undeclared fields with it.
- **Evidence quotes text the way a rule writes a literal**
  ([ADR 35](0035-an-alert-key-names-a-field-the-contract-declares.md)), and
  `strconv.Quote` adds two quotes and writes a control character in four bytes,
  so a raw record of 4,095 or 4,096 bytes — or a shorter one with something to
  escape — was evidence longer than the 4,096 bytes the consumers took.
- **Canonicalisation lengthened what it rewrote**
  ([ADR 5](0005-the-canonical-form-is-for-analysis.md)). Ⱥ and Ⱦ (U+023A and
  U+023E, the only letters whose lower case takes more bytes) are written in two
  bytes and folded into three, so a host name of 127 Ⱥ — 254 bytes, admitted —
  became 381; `1::3:4:5:6:7:8` shortens a single zero group, which its one form
  does not, so beside a long zone an address of 45 bytes became 46. A detection
  carries the canonical origin and its consumers hold the origin to the event
  contract, which says 255 and 45.
- **Two texts had no bound at all where the engine reads them.** The gateway
  stamps `reception.gateway` and `reception.batch_id`, and the event contract
  never held an event to either, so nothing said how long a value a rule asking
  about them could quote.

## Decision

**Every text the event contract carries declares the longest it may be, and the
contract holds every event to it.** `event.LongestText` names it by the path a
rule and a violation use; the suite holds that every text has one and that one
byte more is refused. `reception.gateway` and `reception.batch_id` are held to 64
bytes like any other text, and a gateway named longer than that refuses to start:
it stamps its name on every event it admits, and an event the contract refuses
is answered `422`, which an agent reads as the platform's final word and stops
sending.

**The canonical form of an event is an event the contract takes.** A letter
whose lower case is written in more bytes keeps its case, and an address whose
one form is longer than an address may be is left as it arrived, as text that is
not an address already is. Both only keep apart what the old rewrite merged,
the direction ADR 5 takes when in doubt, and neither touches a value that is
ASCII, which keeps `strings.ToLower`: measured, normalizing an authentication
event that is already canonical went from 292 to 315 ns, where folding every
value a letter at a time would have cost 395.

**A detection carries only what the event contract declares of its event.** The
origin and the instant are copied without the fields this build does not know.
What a producer wrote there is still in the stored event, which the detection
names by agent and identifier
([ADR 34](0034-a-stored-event-is-named-by-the-agent-that-sent-it.md)), and none of
it is something a rule decided; a detection is the engine's own record, written
to the schema this build declares.

**Its consumers take the longest value the engine writes**: evidence of four
times the longest text an event may carry and two quotes, 16,386 bytes for a raw
record of control characters, and a group value as long as the longest text,
4,096. Both are derived from the contract rather than written down a second
time.

**A rule is refused where it is written when a detection of it could encode to
more than `detection.MaxDetectionBytes`.** `Program.Heaviest` measures that by
making the heaviest detection the rule could make, with the code that makes every
detection: one evidence entry for each question — field, operator and polarity,
since an event answers a question about one field in one way and evidence keeps
one entry per answer — holding the longest its field is written in; every field
it groups by at its longest; each stage told by the longest agent and event
identifiers an event may carry; the origin at the longest the contract allows;
every instant and duration at its widest encoding. It counts every question in
the tree, although a disjunction that holds keeps the evidence of one branch, so
it can only overstate what a detection carries. `detection.Compile` refuses the
rule above the ceiling, naming `match` or `sequence`, so a rule tree fails as the
engine loads it, `control-api` reports the fault when it validates the documents
and answers `422` when they are published, and a version read back from the log
holding such a rule is refused whole, as any rule this build cannot compile is
([ADR 15](0015-a-ruleset-is-published-to-a-log.md)). Every detection a compiled
rule makes therefore fits what its topic carries, and the engine's "nothing is
dropped to make progress" holds for every one of them.

| Rule | Heaviest detection |
| --- | --- |
| `ssh.failed_password_from_outside` (shipped) | 1,426 bytes |
| `ssh.repeated_failed_password` (shipped) | 1,389 bytes |
| `ssh.password_guessing_that_succeeded` (shipped) | 1,792 bytes |
| every question of the raw record, both ways | 181,716 bytes, compiles |
| every question of every text an event carries | 288,431 bytes, refused |

The engine-level property test holds every detection the engine made from the
heaviest events the contract admits — every text at its longest, quoted at the
greatest cost, undeclared fields to the event's ceiling, letters and addresses
that canonicalisation used to lengthen — to its rule's heaviest, and to its
consumers' contract: the heaviest detections it makes are within 3% of the
bound.

**A ruleset whose record is heavier than its log carries is refused at
publication**, as the invalid ruleset it is: `422` with the fault, and nothing
published. The largest record a topic carries is what its batch carries less the
64 KiB of key, headers and framing ADR 37 sets aside (`broker.Topic.LargestRecord`,
983,040 bytes for `security.rulesets`), and `control-api` is told it by its
executable from the topology, as every producer is told its batch. The record is
weighed whole, publisher and note included, and only at publication: a version
already on the log was carried, so reading it back weighs nothing (ADR 37's rule
of admission, never of replay). The shipped ruleset is 6,545 bytes.

## What each record the platform makes is bounded by

| Record | Made by | Bounded where | Largest |
| --- | --- | --- | --- |
| detection | `analysis-engine` | when its rule is compiled | 256 KiB |
| ruleset version | `control-api` | at publication | its log's largest record, 960 KiB |
| quarantined record | each writer | by the stream it came from | ADR 37 |
| advisory | `advisory-importer` | as the feed is read | 768 KiB (ADR 37) |
| agent admission | `control-api` | by its fields | under 200 bytes (ADR 37) |

## Consequences

- No shipped rule or ruleset changes outcome, and every detection keeps its name:
  what a detection is named by was never taken from the fields it now leaves out
  (`TestADetectionOfOneAgentsEventsKeepsTheNameItCarriedBeforeStagesNamedTheirAgents`
  still holds the literals).
- A ruleset published before this record, holding a rule a detection of which
  could outweigh what its consumers take, is refused as it is read back, and an
  engine whose active pointer names it keeps running the ruleset it ran. None was
  ever published outside a test.
- A gateway configured with an identifier longer than 64 bytes refuses to start,
  naming `SEAGULL_GATEWAY_ID`.
- A Ⱥ or a Ⱦ in a folded field keeps its case, so a rule asking about one writes
  it as the event did; an address of 45 bytes whose one form is 46 is compared as
  it arrived.
- `TestEveryDetectionTheEngineMakesIsOneItsConsumersTakeAndNoHeavierThanItsRule`
  fails with any of this record's parts removed — undeclared fields copied, the
  quoting cost halved, Unicode folded as `strings.ToLower` folds it, an address
  allowed past its bound, the groups, the host or the stages left out of the
  heaviest, the evidence ceiling put back to 4,096 —
  `TestAnAgentCannotMakeTheDetectionOfItsEventsOneNobodyRaises` drives the first
  three through a real gateway to the shipped rules and alerting document, and
  `TestTheRulesetsTopicCarriesTheHeaviestRulesetTheControlPlanePublishes` fails
  against Redpanda when the framing is not set aside.
- [ADR 5](0005-the-canonical-form-is-for-analysis.md),
  [ADR 7](0007-a-rule-file-is-not-the-rule.md),
  [ADR 11](0011-a-detection-is-not-an-alert.md), ADR 15 and ADR 37 are amended.
