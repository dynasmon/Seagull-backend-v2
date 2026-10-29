# 41. Production is the default and development is declared: an acknowledgement is held by two of three replicas, a limit is turned off only in words, and a body is weighed by what decoding it costs

## Context

The 2026-09-26 security audit made the backbone's transport secure by default
(SEC-04): TLS on unless a deployment turns it off, and an authentication
mechanism a deployment has to name, `none` included. The development Compose
file states its plaintext posture rather than inheriting it. Three defaults that
decide what the platform promises were left where they were, and the 2026-10-02
completeness audit recorded them (AUD-03, AUD-12, AUD-13; BE-046):

- **`SEAGULL_BACKBONE_REPLICAS` defaulted to 1, and the in-sync minimum to a
  majority of that, 1.** A deployment that set nothing created every topic with
  one copy, and the `durable` in every acknowledgement an agent drops its spool
  on ([ADR 1](0001-durable-before-acknowledged.md)) meant one disk.
- **`*_RATE_PER_SECOND=0` turned a limiter off without a word**, at the gateway,
  the control plane and the query plane: `ratelimit.Limiter` admitted everything
  at a rate of zero, so a setting meant as a number silently removed a security
  control.
- **The gateway counted what it holds in wire bytes.** `SEAGULL_GATEWAY_MAX_INFLIGHT_BYTES`
  reserved a body's length before reading it and nothing for what decoding it
  costs.

Measuring the third found it worse than recorded. Decoding a body allocates far
more than the body weighs, and how much more is the sender's to choose:

| Body | Decoding allocates |
|---|---|
| 1,000 authentication events as an agent sends them | 4.8 times the body |
| 10,000 packages as dpkg reports them | 2.7 times |
| 16 status reports | 5.8 times |
| 16 assessments | 3.7 times |
| 8 MiB of empty events | 77 times: 643 MB |
| 8 MiB of empty status reports | 133 times: 1.1 GB, 974 MB of it held |

A Go message decoded into a struct costs the struct whatever the bytes on the
wire, and an empty message is two bytes. Every count ceiling the gateway keeps —
events per batch, records, items, reports — is checked after the batch is
decoded, so none of them bounds this. One registered agent, compromised or
broken, could make a gateway configured to hold 128 MiB allocate gigabytes, and
no single factor documented beside the setting could have bounded it.

Two facts about the backbone shape the report below. Redpanda acknowledges a
write sent with `acks=all` once a Raft majority of its replicas holds it, and it
accepts `min.insync.replicas` without answering for it: v24.2.20 reports no such
setting on a topic. Kafka acknowledges once every in-sync replica holds the write
and refuses one below `min.insync.replicas`.

## Decision

**A production backbone keeps three replicas of every record and acknowledges
one only once two hold it; anything less is declared.** `SEAGULL_BACKBONE_REPLICAS`
defaults to 3 and `SEAGULL_BACKBONE_MIN_INSYNC_REPLICAS` to a majority of them,
2: losing a broker loses nothing the backbone acknowledged, and the backbone
keeps acknowledging. `SEAGULL_BACKBONE_DURABILITY` is `production` unless a
deployment says `development`, and `Topic.Validate` refuses a production topic
that keeps fewer than three replicas or acknowledges a write fewer than two hold
(`ErrBelowProductionDurability`, naming the setting that admits it). Every
process validates its topics before it serves and `backbone-migrator` before it
asks the broker anything, so a deployment that set `REPLICAS=1` and nothing else
starts nothing. The development Compose file declares `development` beside its
one replica, as it declares plaintext. The posture is judged where replication
already was — `Topic.Validate` refuses more in-sync replicas than replicas — and
the zero value of `Durability` is `production`, so a topic built in code is held
to the floor unless it says otherwise.

**Every process says at startup what an acknowledgement is worth.** Once its
topics are verified, a process logs `backbone_durability` — the durability, the
replicas, the in-sync minimum and `acknowledged_by` — and exports
`seagull_backbone_acknowledging_replicas`, the fewest replicas that hold a record
once the backbone acknowledges it. That is the fewer of the in-sync minimum and
a majority of the replicas: what Kafka guarantees and what Redpanda does, so the
number is never more than either broker keeps. It is read from the declaration
once verification has held it to the broker — the replicas exactly, the in-sync
minimum at least where a broker answers for it — and reported for the topic
whose acknowledgement is worth least. Under `development`, or below two, the line
is a warning. The gateway reports the four topics it acknowledges agents into,
`control-api` the ruleset and agent topics, the engine the events it reads and
the detections it makes, the advisory importer what it publishes, every writer
and projector what it consumes and, where it has one, its quarantine, and the
migrator the topology it applied.

**A limit is at least one, and a limiter is turned off only by the word
`unlimited`.** `SEAGULL_GATEWAY_RATE_PER_SECOND`, `SEAGULL_CONTROL_API_RATE_PER_SECOND`
and `SEAGULL_QUERY_API_RATE_PER_SECOND` refuse `0` at startup and read
`unlimited` (`config.Parser.Limit`); a process told `unlimited` builds no
limiter and logs `rate_limit_off` as a warning naming the setting. A limiter
always limits: at a rate of zero it grants its burst and nothing after, so no
number can turn one off again.

**The gateway weighs a body before it decodes it, and holds what decoding it
would allocate.** The body is still reserved before it is read; once read, it is
walked in its wire form, which allocates nothing, and weighed: a message costs
the struct it is decoded into, a text its copy, a list element its slot, a field
the contract does not declare its bytes, kept as they arrived, and a oneof the
wrapper a decoder makes before it reads the wire type — so a oneof sent with the
wrong wire type costs its wrapper as well as its bytes. Every term is a bound:
a slice grown one element at a time allocates up to eight times what it ends up
holding, and an allocation up to a quarter more than it asked for, plus sixteen
bytes. The struct sizes are read from the generated types when the route is
built, and a route whose batch reaches a map or a group refuses to start,
because nobody measured how a decoder allocates them. Then:

| What the weighing finds | Answer |
|---|---|
| a body that is not protobuf | `400 malformed_payload`, as before |
| the body and its weight exceed everything the gateway holds | `413 batch_too_large`: the agent splits the batch, and sets aside a record it cannot split |
| they fit, but not beside what is in flight | `503 gateway_at_capacity` with `Retry-After`: the agent sends it again |
| they fit | the reservation grows to them, and the body is decoded |

A batch too heavy to decode is refused as too large rather than as a gateway at
capacity because only the first is an answer sending again can change: a deployed
agent splits a batch refused as `batch_too_large` and refuses for good a single
record refused that way, and it would send a `503` again for as long as it was
sent. `SEAGULL_GATEWAY_MAX_INFLIGHT_BYTES` therefore counts what the requests in
flight hold — each body and what decoding it allocates — and its default stays
128 MiB, now meaning what it says.

The bound is proven, not argued. A test builds, for every field each of the four
batches can reach, a body repeating that field at its emptiest inside the
shortest path of empty messages to it, the same field sent with the wrong wire
type, and a field its message does not declare — about 580 bodies, regrown with
every contract release — plus a oneof switching between two kinds, texts at every
allocation-class edge and the honest batches above, and holds what decoding each
allocates to what it was weighed at. The bodies end two bytes past a slice's
growth step, where growing costs most: a growth factor of five, which an earlier
model used, fails 238 of them. Each term was removed in turn and a test failed.

| Honest batch | Body | Decoding allocates | Weighed at |
|---|---|---|---|
| 1,000 authentication events | 274,884 bytes | 1,313,544 | 2,183,154 |
| 10,000 packages | 1,910,111 bytes | 5,190,944 | 9,091,170 |
| 16 status reports | 7,070 bytes | 40,840 | 84,074 |
| 16 assessments | 4,526 bytes | 16,776 | 36,474 |

An honest batch is weighed at 1.7 to 2.2 times what decoding it allocates — the
price of terms that are bounds — and a hostile one at what it would cost.
Weighing a 1,000-event batch takes 420 ns an event and allocates nothing;
decoding it takes 2.2 µs an event.

## What this deliberately does not do

**It does not answer for whether a replica has written a record to disk.** An
acknowledgement is a replication guarantee: a majority holds the record. Kafka
acknowledges from memory and Redpanda can, with `write.caching`, which a
production Redpanda leaves off and the default configuration of its container
image, which the development stack runs, turns on. Which one a
deployment runs is its operator's decision, and the platform states the
replication it verifies rather than inferring the broker beneath it.

**It does not reserve the encoded copy a publish holds.** After admission each
record is encoded again and held until the backbone acknowledges it: 2.85 times
the body of an event batch, about 530 bytes a record beyond the record itself,
and about the body for a batch of large records. It is bounded by what admission
let through — every record already validated, its weight checked against its
topic ([ADR 37](0037-a-record-is-bounded-by-what-its-topic-carries.md)) — and
the cost is the publisher's, which the gateway's admission does not see; the
configuration reference states it beside the setting so a host is sized for it.

**It does not refuse a body for being dense.** A body is refused only when it
could never fit, so a valid record unusual enough to weigh more than the gateway
holds is set aside by the agent, and the answer to that is a larger capacity, not
a density rule that would refuse records which honestly fit.

**It does not grant per-component backbone principals** — that is BE-004 — and it
changes nothing an agent sends: the agent already splits a batch refused as too
large.

## Consequences

- **A deployment that set nothing now asks for three replicas.** Topics an older
  release created with one replica no longer agree with the declaration, so every
  process refuses to start until the deployment either declares
  `SEAGULL_BACKBONE_DURABILITY=development` beside `SEAGULL_BACKBONE_REPLICAS=1`
  or reassigns its partitions to three replicas — an operator's operation, which
  the migrator refuses to perform. The development Compose file declares it.
- **A deployment that set a rate of `0` refuses to start** until it writes
  `unlimited` and accepts the warning.
- **An agent sees `413 batch_too_large` for a body that would cost more to
  decode than its gateway holds, and `503 gateway_at_capacity` sooner for heavy
  batches**, because the capacity now counts what they hold. A gateway that used
  to admit 32 concurrent batches of 10,000 events — weighed at about 800 MB at
  once — does so only with the capacity sized for it; the load suite holds 1 GiB
  for that scenario.
- [ADR 1](0001-durable-before-acknowledged.md) is amended: by default `durable`
  means that at least two of three replicas hold the batch.
