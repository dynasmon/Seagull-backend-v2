# 55. An asset is assessed whole again when its feed turns fresh, rather than at its next inventory

## Context

[ADR 49](0049-a-finding-is-decided-by-one-reader-from-the-stores-their-owners-filled.md)
assesses an asset whole when its inventory names it, and an advisory change judges
the packages of the assets holding what it names. It listed among what it
deliberately does not do: "No re-evaluation when a stale feed recovers. The next
inventory record of each asset (agents send one a day) decides it again."

The end-to-end test of 2026-11-20 measured what that costs, on a real Ubuntu 24.04
host and the standard installation:

- the first read of the Ubuntu feed took 48 minutes. An asset assessed during it
  was `STALE_INTELLIGENCE`, because the feed had never been held whole;
- the read ended at 17:24. At 17:38 the asset's newest whole assessment was still
  the one from 16:48, and nothing would have changed it before the agent's next
  package inventory, up to a day later;
- meanwhile the advisory trigger judged the asset's packages and opened 33,714
  findings, so the asset read as not assessed beside tens of thousands of open
  findings. A package change on the host was what assessed it, 36 seconds later.

Every installation goes through this once per feed, at the moment somebody first
looks at it, and again after any outage of a feed longer than the freshness
bound. Nathan decided on 2026-11-20 to amend ADR 49.

## Decision

**A feed sync that makes a feed fresh assesses whole every asset whose
distribution that feed covers, in the batch that carries the sync, as an
inventory record of the asset would.**

### When a feed turns fresh

A sync record says when the platform last held everything the feed listed,
`synced_at`, and an attempt that did not complete carries the previous one
forward. A sync record turns its feed fresh when it holds the feed whole and:

- no attempt before it ever held the feed whole, which is the end of the first
  read; or
- the attempt before it held the feed whole longer ago than the freshness bound,
  which is the end of a gap in which an asset could have been judged stale.

"Before it" is the newest attempt of the same source and feed whose `checked_at`
is earlier, read from `vulnerability_feed_syncs` once the advisory writer has
stored the batch (the settle of ADR 49). A sync within the bound of the one
before it, and an attempt that never held the feed whole, decide nothing.

### Which assets it assesses

Every asset whose newest operating system item places it in an ecosystem the feed
is read for (`vulnerability.EcosystemOf`, `vulnerability.FeedOf`), read from
`asset_inventory` by `clickhouse.MatchingReader.Systems`. Each is assessed exactly
as an inventory trigger assesses it: read from the store through ADR 27's rule for
what is current, against the newest intelligence, labelled against its newest
decisions. An asset the batch already assesses whole is assessed once.

A feed read by more than one source is as fresh as the stalest of them, and the
trigger looks at one source at a time. A source turning fresh while another is
still stale assesses the assets again, and they come out stale again: work done
twice, never a decision made on less than what the store holds.

### Replay

The previous attempt is read from the store, which keeps a year of attempts, and
the assets from the inventory store as it stands, as every trigger reads it. A
replayed sync whose previous attempt the store no longer keeps is treated as the
first, which assesses its assets once more and decides what the store says.

## What this deliberately does not do

- **No narrowing to the assets that were stale.** Every asset the feed covers is
  assessed, including one an inventory record assessed after the sync. It is one
  more whole assessment per asset per event, and the events are the first read of
  a feed and the end of an outage.
- **No assessment split across batches.** The assets a sync names are assessed in
  the batch that carries it, and a batch that fails is decided again whole, as
  every batch is. For a fleet of many thousands of assets of one feed, that batch
  is the matcher's longest, and it is measured before it is trusted.
- **No trigger on an advisory written during the first read.** Those still judge
  the packages of their holders, as ADR 49 says; the sync that ends the read is
  what assesses the assets whole.

## Consequences

- `matching.Inventory` gains `Systems` and `matching.Intelligence` gains
  `Synced`, both read-only, through `clickhouse.MatchingReader`.
- `seagull_matching_triggers_total{kind="feed"}` counts the syncs that assessed
  assets and the ones ignored.
- The cost of a feed turning fresh is one whole assessment of every asset it
  covers, about what one day of inventory costs; ADR 49's daily round already
  implies the matcher can afford one.
