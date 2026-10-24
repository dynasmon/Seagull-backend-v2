# 36. Detection state is read back from the last record a reader committed, never from the clock

## Context

[ADR 23](0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md)
rebuilds a window by putting the reader back to the first record inside the
window the running rules need. It measured that window back from `time.Now()`,
which is the window the process was in only when it was not behind.

A process stopped, or lagging, for longer than its recovery resumes at a
committed position older than the clock minus the recovery. The broker then
answers an offset at or past that position, nothing is read back, and every
window that was open when the process stopped is decided again from empty state.
With the shipped rules the recovery is ten minutes — the five-minute sequence
window plus five minutes of clock skew — so any outage, crash loop or lag longer
than that loses the detections whose windows straddle the stop. ADR 23's "the
reader is never moved forward" treated the reader behind its window only to
forbid skipping, and nothing reported the loss: the rebuild counters count the
rewinds that happen, not the ones that should have.

An external review of `43e828a` found it on 2026-10-23 (BE-091), and
`TestAProcessDownLongerThanItsRecoveryStillReachesTheThreshold` reproduced it
against Redpanda: fifteen failures decided and committed, five more admitted
while the engine was down, the engine back once its recovery had passed — no
detection, where a run that never stopped decides one.

## Decision

**The window is measured back from the last record each partition committed.**
At every assignment, for each partition with a committed position, the reader
reads the record just before that position and is put back to the first record
at or after that record's timestamp minus the recovery. Each partition is
anchored on its own record: one anchor for all of them would let an idle
partition, whose last record may be days old, drag every other partition days
back.

**That record is read by a client of its own.** The assignment callback holds
the group session, so the reader's own client fetches nothing until the
callback returns. A short-lived client reads one batch per partition, bounded at
thirty seconds, and closes. Where each window starts is then asked in one
listing that carries a timestamp per partition, because a listing at one
timestamp per call would cost a request per partition of a reader that may hold
a thousand.

**A window the topic no longer holds is reported, never rebuilt quietly from
less.** The reader first asks where each partition starts, and tells two cases
apart: retention removed records the reader never decided, because its position
is older than the oldest record held (`undecided_records_gone`), or it removed
the record the partition stopped after, so nothing can be read back
(`last_committed_record_gone`). Each counts
`backbone_state_rebuild_incomplete_total` by topic and partition and logs
`state_rebuild_incomplete` with the partition, the position and the reason. The
reader keeps going: what remains is the best state it can hold, and stopping
would not bring the removed records back.

**A window cut in the middle is not reported, because it cannot be told from an
idle partition.** A read back that lands on the oldest record held may have lost
the part of the window before it, or the records retention removed may all be
older than the window; telling them apart needs the timestamps of records the
broker no longer has. Reporting every such landing was tried and rejected on the
development stack: a sparse partition, whose last burst fits inside one window
and whose older records retention removed, raised it on every restart, and an
alarm that fires on every quiet agent is one nobody reads. Time-based retention
removes a record only once it is older than the retention, so a window cut in the
middle means a reader within one recovery of the retention edge — which is
losing undecided records too, and that is reported.

**What does not change.** A reader is never moved forward. A backbone that
cannot say where a partition starts, or what it last committed, stops the reader,
as ADR 23 decided for the window itself. The recovery — the longest running
window plus the clock skew — is unchanged.

## Consequences

- A restart reads back at most one recovery of records per partition, wherever
  the reader stopped. A partition that was idle reads back the window before its
  last record, which a process that never stopped would still have held.
- Every assignment opens one more client, asks where the partitions start, and
  lists where each window starts in one more request. Assignments happen at
  startup and at rebalances, never per batch.
- A lag longer than the topic's retention loses telemetry before it loses a
  window, and the consumer's own reset to the oldest record held says nothing;
  `undecided_records_gone` is what says so.
- `TestAProcessDownLongerThanItsRecoveryStillReachesTheThreshold` is the
  regression test, and the unit tests in `internal/broker/recovery_test.go` hold
  the anchor per partition, the two reports and the sparse partition that must
  not raise one.
