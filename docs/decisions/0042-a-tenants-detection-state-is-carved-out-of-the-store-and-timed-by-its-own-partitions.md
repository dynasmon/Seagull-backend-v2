# 42. A tenant's detection state is carved out of the store and timed by its own partitions

## Context

[ADR 18](0018-detection-state-is-a-bounded-window.md) bounded what a rule
remembers and decided that a store at its ceiling refuses a new key rather than
evicting one, because a flood must not choose which real counts an estate forgets.
That was right and it looked at one estate. The 2026-10-02 completeness audit found
what it leaves between tenants (AUD-07, BE-048), and three things follow from one
map with one ceiling and one watermark:

- **One tenant could spend the whole store.** Whoever produces events produces
  group values, so one compromised agent sending invented source addresses filled
  the ceiling, and every counting and sequence rule of every tenant stopped
  opening keys. Reproduced with the shipped rules and the default store: 8,192
  invented addresses in one tenant, and twenty failures and a success in another,
  decided neither of that tenant's stateful rules.
- **A flood also stalled the engine.** A store at its ceiling walked every key
  before refusing a new one, on every event, holding the lock. Measured, one
  refused event cost 98 µs at the default 4,096 keys and 157 ms at a million: about
  six events a second, for every tenant, for as long as the flood went on.
- **One watermark timed every partition.** A key is reclaimed once the stream has
  moved past its window, and "the stream" was the newest event anywhere. A partition
  read back after a rebalance, or simply behind, has its own place in time: under
  pressure, the window it was in the middle of reading looked long past because
  another partition had run ahead, and it was reclaimed. A count that started again
  there broke what [ADR 23](0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md)
  promises, and the gateway lets a producer's clock run five minutes ahead, so any
  agent could move that one watermark for everybody.

## Decision

**The ceiling on keys is carved into a quota per tenant and per rule, and neither
adds to it.** `Bounds` declares `KeysPerTenant` and `KeysPerRule` beside `Keys`,
each at least one and at most what it is carved from.
`SEAGULL_DETECTION_STATE_KEYS_PER_TENANT` defaults to a quarter of the store and
`SEAGULL_DETECTION_STATE_KEYS_PER_RULE` to half of that. A quarter means one tenant
alone cannot fill the store, and four must flood together to do it; a deployment
with one tenant states so by giving it the whole store. The keeper counts what each
tenant and each of its rules holds, so a `Key` keeps the tenant and the rule legible
beside the digest of its group. A key already held goes on counting at any quota,
and nothing is ever evicted: ADR 18's reasoning holds for a quota exactly as for the
ceiling.

**A refusal names what overflowed**: `ErrTenantAtCapacity` when the tenant has used
its quota, `ErrRuleAtCapacity` when only the rule has, `ErrAtCapacity` when the store
has, and they are counted as `tenant_at_capacity`, `rule_at_capacity` and
`at_capacity`. A tenant's quotas are checked first, so a tenant at its own limit is
told so and never reaches the walk below: refusing it costs what refusing it should.

**What a tenant's pressure reclaims is that tenant's own.** A quota can be reached
far more easily than the ceiling was, and a tenant may hold a clock ahead of
everyone's; if its pressure reclaimed what was past for anyone, a flood would be a
way to make another tenant's live count start again, which is what ADR 18 refused.

**A watermark belongs to one tenant on one partition.** BE-048 asked for one per
partition. That keeps a partition behind the stream from being judged by one ahead,
but tenants share partitions: one agent's clock would still decide what another
tenant's keys look like. Keyed by both, what a tenant sends moves no watermark of
another's, and on a partition that delivers, a key is past only when its own
tenant's events there have moved beyond its window. Keys are filed by the partition
that opened them: under a rule the stream keeps together that is the only one
feeding them, and a key a sole reader holds across partitions is timed by the first
of them, which costs it at most a count that starts again, under pressure.

**A partition that stops delivering is carried on by the rest of the stream.** A
watermark of its own would stand still once a partition went quiet or this process
lost it, and its keys would hold their tenant's room for good; ADR 23 leaves those
keys to be reclaimed like any other and relied on the watermark being shared. So
each partition remembers how far the whole store's stream had got when it last
delivered, and its clock is

```text
clock = watermark + (newest event anywhere - newest event anywhere when it last delivered)
```

While it delivers that is its watermark, however far behind, so it keeps what it is
still reading. Once it stops, it runs at the pace of everything else from where it
stopped, keeping the distance it had. The clock is never ahead of the newest event
seen, so what a producer can do with it is what ADR 18 already bounded: at most the
skew the gateway admits, on a partition its tenant is not delivering on, and only
under that tenant's pressure or at the ceiling.

**Reclaiming follows an index, kept only under pressure.** Each tenant's partition
holds a min-heap of its keys by the first moment each could be past. A key only ever
moves later, so folding leaves the heap alone and a store with room pays nothing for
it, which is what ADR 18 asked of reclaiming. Reclaiming pops what is past and files
again whatever was observed since, each at most once for the observations that moved
it, so its cost follows what it finds and never how much is held.

**A store at its ceiling asks every tenant once a second of the stream.** Quiet
tenants feel no pressure of their own, so only the ceiling can take their keys back,
and that means walking every tenant on every partition. A flood reaches the ceiling
on every event, so the walk runs at most once per second of event time. A tenant
asking for room always reclaims its own keys at once, and a key gone past since the
last walk is refused room for that second at most, and is never miscounted.

**Every refusal is counted and few are told.** No metric may carry a tenant or a
rule, so `detection_state_at_capacity` names them in the log, once per tenant, rule
and outcome and for at most 1,024 of them. `detection_state_fullest_tenant_keys` and
`detection_state_fullest_rule_keys` beside their ceilings are the headroom before
anything is refused.

**A refusal that lasts is an alert.** `deploy/prometheus/detection-state.yml` holds
the platform's first alert rules: refusals sustained for ten minutes, critical for
the store and for a tenant, because a rule that cannot open a key is blind to that
group, and a warning for one rule. A burst a quota stopped is what a quota is for and
raises nothing. `make test-alerts` evaluates them against recorded series, and
`TestTheDetectionStateAlertsReadWhatTheEngineCounts` holds them to what the engine
exports, since neither would otherwise notice the other being renamed.

## Consequences

- Below its quotas, what a tenant decides depends on nothing another tenant sends,
  and `TestAProcessThatReadBackOverItsWindowDecidesWhatOneThatNeverStoppedDid` still
  holds. As before, which keys are refused under pressure follows the order
  partitions are read in, so a restart inside a flood can refuse different ones; that
  is counted, and it is confined to the tenant over its quota.
- Measured on one core of a Ryzen 7 5700X, against the same benchmark on the commit
  before this one:

  | Operation | Keys | Before | After |
  |---|---|---|---|
  | Refuse a new key, every key live | 4,096 | 98 µs | 197 ns |
  | | 1,048,576 | 157 ms | 330 ns |
  | Reclaim the one key past its window | 4,096 | 109 µs | 1.1 µs |
  | | 1,048,576 | 169 ms | 1.9 µs |
  | Fold the busiest 1% of keys | 4,096 | 247 ns | 300 ns |
  | | 1,048,576 | 628 ns | 756 ns |

  A fold pays a fifth more for the clock's two lookups, a wider key and a wider
  observation, which comes to 1% of an event: one read through the shipped rules
  costs 33.7 µs where it cost 33.3 µs. The walk at the ceiling costs 60 µs across 100
  tenants on 12 partitions and 800 µs across 1,000, once a second of the stream;
  every refusal in between costs 255 ns.
- **The index has a price, and it is paid once.** The first time a store runs out of
  room with its keys moved since it last looked, one reclaim files them all again:
  0.5 ms at 4,096 keys and 275 ms at a million, then under 4 µs. The alternative,
  keeping the heap in order on every fold, costs every event in every store another
  25 to 130 ns at the default size and 200 to 450 ns at a million, to avoid a pause
  that happens once.
- A full default store holds 140.1 MiB where it held 139.3 MiB. A key holding one
  observation, which is what a flood opens, costs 833 bytes where it cost 661.
- A rule is charged by its identifier, so the keys of a revision it replaced count
  against it until they are past. It only matters to a rule at its quota, for one
  window, and the tenant's room is not spent twice.
- **What this leaves open.** A compromised agent still blinds its own tenant: quotas
  stop at the tenant and the rule, and an agent quota was not asked for. Four tenants
  flooding together, or honest tenants holding all but what one flood takes, reach
  the ceiling, and then everybody is refused; the alert says so and
  `docs/configuration.md` says how to size for it. The quotas are one number for
  every tenant; a quota per tenant is BE-090's, with the tenant registry it needs.
  The rest of the platform's alerting, and a Prometheus to run it, is BE-040's.
- `TestTheIndexReclaimsExactlyWhatAWalkOverEveryKeyWould` holds the index to a walk
  over every key through random streams, out of order, behind the stream and under
  every quota. `TestATenantUnderPressureReclaimsNothingOfAnothers`,
  `TestAPartitionBehindTheStreamKeepsItsKeys`,
  `TestAPartitionThatStoppedDeliveringLetsItsKeysGo` and
  `TestAStoreAtItsCeilingAsksEveryTenantOnceASecondOfTheStream` hold the decisions
  above in `internal/detectionstate`; `TestAFloodInOneTenantLeavesTheShippedRulesDecidingForAnother`
  runs the shipped rules at the default bounds, and
  `TestATenantFloodingGroupValuesLeavesAnotherTenantsRuleDeciding` and
  `TestARestartBesideAFloodStillReachesTheThreshold` do it against Redpanda. Each of
  thirty injected defects failed at least one of them.
