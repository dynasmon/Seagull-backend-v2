# 43. A record keeps apart what one identity would fold

## Context

[ADR 27](0027-inventory-is-a-record-kind-of-its-own.md) identified a package by
its name, architecture and manager and an account by its uid, so that an upgrade
and a rename replace a row instead of adding one. The 2026-10-02 completeness
audit found what that leaves out for packages (AUD-09, BE-049), and the card asked
for a declaration of which packages a manager can install in parallel, drawn from
the manager's semantics and never from name patterns, with no contract change.

Reading what each manager does, on real systems, changed the question:

| Manager | What its database held of one name and architecture | Seen on |
|---|---|---|
| dpkg | One. Eight installed kernels are eight names, `linux-image-7.0.0-38-generic` and its like, and none of 2,173 packages repeats | Ubuntu 24.04 |
| apk | One. Asked for `jq=1.7.1-r0` and `jq=1.6-r4` together, it downgraded the first and kept the second | Alpine 3.20 |
| rpm | As many as it was given. `kernel-core` and `kernel-modules-core` twice each, `gpg-pubkey` twice with `(none)` for an architecture, and `openssl-libs` at `1:3.5.8-1.el9_8` and `1:3.5.8-2.el9_8` | Rocky Linux 9 |

Three things follow from the rpm line, and each rules out an obvious answer:

- **"Install-only" is not rpm's word, and it is not on the wire.** It is dnf's
  `installonlypkgs`, matched against what a package `Provides`:
  `installonlypkg(kernel)` on `kernel-core`. The contract carries no such thing.
  A list of names kept here would drift from it; the audit's own list of three
  already misses `kernel-modules-core`.
- **What a database holds is wider than what install-only says.** No `Provides`
  and no list names the keys or `openssl-libs`. The second `openssl-libs` went in
  with `rpm -i`, and `dnf check --duplicates` calls it a duplicate, which is the
  state an interrupted transaction leaves behind. It is also the very case the
  card worries about: a version the database still lists although a newer one
  arrived.
- **Every kernel of a release shares `%{VERSION}`.** Both were `5.14.0`; only
  `%{RELEASE}` told them apart.

Reproduced against ClickHouse: a record naming two kernels left one row, the one
named last, so which version an asset appeared to hold was decided by the order of
the list.

The same collapse is reachable today, and by the only agent that exists. An
account is identified by its uid, and a second account of uid 0 is how a backdoor
is kept. The agent sends both and warns locally (`inventory_items_merged`,
`user "0": "root", "toor"`) that the platform will keep one. Reproduced: a record
naming `root` and `toor` left `toor` alone in the store, and the other order would
have left the backdoor out of it.

## Decision

**An identity says what an item is; a record says how many there are. Where a kind
can hold several items under one identity, a record that shows several names each
by what tells them apart as well.**

- A package adds its version; an account adds its name.
- One item shown alone keeps the identity ADR 27 gave it, byte for byte.
- `inventory.ItemIDs` is the only way to name an item. It takes a record, and the
  function that names one item alone is no longer exported, because it would
  answer wrongly for every kernel.

### A snapshot is the manager speaking

A snapshot is the whole of what a manager holds, so two versions of one name and
architecture in it are that manager saying both are installed. That is its
semantics, stated at the moment they apply, on the host they apply to, for every
case above, and it takes no list of names and no field on the wire. It is what the
card asked for in the one form the platform can actually read it.

What is declared is the reverse: the managers that **cannot** hold two.

```go
var heldOnce = map[string]bool{"dpkg": true, "apt": true, "apk": true}
```

A package of those managers never takes its version, so no package an agent sends
today changes name. Everything else, `rpm`, `dnf` and `yum` included, follows the
record. A manager nobody declared is treated as able to hold several on purpose:
wrongly listing one folds two instances into a row, and wrongly leaving one out
only costs a name.

### A version shown alone is the package

The version does not go into the identity of every rpm package, which is the
audit's other suggestion and would have been one line. An upgrade under it would
add a row rather than replace one, against the card's own criterion, and BE-036
names a finding by its item and needs `fixed` to be a state a finding moves to:
were `openssl-libs` a new item at every release, an upgrade past a fix could not be
told from a removal. Only what a record actually shows as several pays for being
several.

### A delta names the instance it saw

A delta shows part of an asset, so it cannot say a version replaced another. On a
manager that can hold both, it names the instance it saw and retires nothing, which
is what ADR 27 already says of a delta. Naming it as a snapshot would have let a
delta announcing a second kernel overwrite the first, the defect this decision
closes, through another door. The price is on the safe side: a version a delta
upgraded away stays current until the next snapshot, and a delta repeating a
version a snapshot showed alone leaves two rows saying the same thing. An instance
is reported for too long rather than not at all, which
`TestADeltaNeverCostsAnAssetAnInstance` holds over generated histories. A manager in
`heldOnce` keeps replacing, as it always did. Nothing sends a delta today.

### Replay and order

An identity is now a function of its record rather than of its item, and it is
still a function: the same record names the same items in any order, so a replay
lands on the rows it wrote. An instance that gains or loses a sibling changes name
between two scans, and the line of ADR 27 handles that with nothing added: the row
under the old name is out of the answer as soon as a snapshot stops naming it. One
kernel, then two, then the older gone leaves the right answer at every step, in
ClickHouse and in a generated test folding scans in any arrival order.

## What this deliberately does not do

**No contract field.** `Package` could carry the manager's opinion, as a flag the
collector reads from `Provides`, and it would declare less than the snapshot
already shows: nothing would set it for a key or a duplicate. It would need a
release, a store column and an agent that reads rpm, and no agent does.

**No refusal of a record that contradicts its manager.** A dpkg record naming two
versions of one name and architecture cannot come from dpkg. It stays what it was,
one row, the one named last: refusing it would cost the asset its whole package
list, and whoever can forge that record can already leave a package out.

**Nothing for the other kinds.** Their identity is what their source already keys
them by: systemd holds one unit of a name, a network namespace one interface of a
name, and a pid namespace one process of a pid and a start. A package and an account
are the two kinds whose identity is wider than their source's key, deliberately, so
that an upgrade and a rename land on the row they replace.

**No change to what a record may hold.** Nothing here is checked at admission, and
the gateway derives no identity.

**No reader.** How an asset's instances are read back is BE-061's.

**No version ordering.** Choosing which of two kernels matters is BE-036's, and it
needs an order that does not exist yet.

## Consequences

- **Nothing stored moves.** No schema change and no migration: `item_id` is a string
  the sort key already holds, every identifier of an item shown alone is unchanged,
  and `TestWhatAStoreAlreadyHoldsKeepsItsName` holds them to digests worked out
  outside the code.
- **`Package.version` has to be the whole version.** A collector reporting
  `%{VERSION}` alone would give every kernel of a release one version and fold them
  again. `seagull.inventory.v1` says so now, and BE-036 needs the same field to
  compare with.
- **BE-036 must name items through `ItemIDs`, and a finding can change name.** An
  instance that gains a sibling is renamed, so a finding named by its item has to
  be carried across that by package and version, or read as a new one. It happens
  when a host goes from one kernel to two, not at every upgrade. Which kernel is
  the one running stays in `KIND_KERNEL`, a singleton and a separate fact.
- **A reader counts instances, never rows.** Two current rows can say the same thing
  after a delta, and a version's history is in `package_version`, not in one
  `item_id`.
- **The agent's mirror is out of date in one place.** `protocol.InventoryIdentity`
  stays true for everything it sends but for an account sharing a uid, where
  `inventory_items_merged` now warns of something a platform of this release no
  longer does. It is a local warning, and agent releases keep working unchanged:
  no answer on the wire differs.
- **What it costs is not measurable where it matters.** Projecting a record of
  10,000 items took 6.4 ms under dpkg before and after, and 6.6 ms rising to 6.9 ms
  under rpm, where that call allocates 1.5 MB more on the 12.6 MB it did.
- **A second account of uid 0 is now in the store.** Nothing raises anything on it
  yet: the read plane is BE-061 and a rule over inventory does not exist, so this
  makes the fact available rather than making it an alert.
