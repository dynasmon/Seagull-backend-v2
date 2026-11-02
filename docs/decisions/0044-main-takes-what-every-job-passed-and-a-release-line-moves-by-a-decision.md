# 44. Main takes only what every job passed, what runs is named by its digest, and a release line moves by a decision

## Context

Three public repositories make one security product, and until now nothing stopped
unverified code from reaching any of them. The 2026-10-02 completeness audit recorded
it (AUD-10, AUD-11, AUD-15; BE-050):

- **Nothing had to pass.** The backend has held a ruleset since 2026-10-25 that refuses
  deleting `main` and force-pushing to it, and requires nothing else; the agent and the
  contracts have no rule at all. Contracts #28 merged three seconds after its checks
  began, and `backward compatibility` then failed on it. Of the backend's last sixty
  runs on `main` and its branches, six were cancelled by the push that followed them.
- **What runs was named by a tag.** ClickHouse 24.8, Redpanda v24.2.20, PostgreSQL 16.4
  and Prometheus v3.5.0 were all outside their support, a registry can move a tag, and
  no image was scanned.
- **Three toolchains.** The backend was on Go 1.26.10, the agent on 1.26.9, which links
  a `crypto/x509` vulnerability fixed in 1.26.10, and the contracts on 1.25.13, whose
  line is out of support.
- **Nobody was watching.** No Dependabot, no CodeQL, and `tools/buf` of the contracts
  held 28 known vulnerabilities in packages it links, unnoticed since 2024.

## Decision

**A change reaches `main` through a pull request every job passed, with no one able to
bypass it; every image and action is named by what it is rather than by a name its
owner can move; and a release line moves only as a decision, after its defaults were
compared.**

### What main takes

`.github/rulesets/main.json` is the rule, in a form GitHub imports, and it is the same
in the three repositories but for the job names: no bypass actor, not even the owner; a
pull request, merged by a merge commit only, because a contracts tag and the commit the
agent's evidence names must stay in history; no deletion, no force push; and every job
of `ci.yml` and `codeql.yml` required, each reported by GitHub Actions
(`integration_id` 15368), so a token that can post a commit status cannot satisfy one.
No approving review is required, because the repositories have one maintainer and
GitHub refuses an author's approval: the rule is that the jobs passed.

The rule lives on GitHub and a file does not enforce it, so two checks hold the file to
the world. `TestEveryJobIsRequiredOnMain` refuses a job the ruleset does not require,
which a renamed or new job would otherwise silently be. `make check-protection`, on the
daily schedule, compares what GitHub enforces with what the file declares.

A push to `main` no longer cancels the run of the push before it: `main` is grouped by
commit, so every commit on it finishes its CI. In the contracts, `backward compatibility`
moved to a workflow of its own that only pull requests run, because a job skipped by
`if:` reports success under the name a rule requires.

### What runs is named by what it is

Every image in `deploy/` is named by its digest, every action by its commit, and every
workflow grants its jobs `contents: read` unless a job asks for more.
`TestEveryImageIsNamedByItsDigest`, `TestEveryActionIsNamedByItsCommit` and
`TestAWorkflowWritesNothingUnlessAJobAsks` hold them there.

Dependabot proposes updates to Go modules, actions and images, with a cooldown of seven
days, so that a compromised release has a week to be caught by somebody else before it
is proposed here; security updates do not wait. `Seagull-contracts` is ignored, since a
release of it is a contract decision and, in the agent, needs new recorded evidence.
`tools/buf` declares its tools with `tool` directives, because a module of no Go files
loses every requirement to `go mod tidy`, and a Dependabot update would have emptied it.

### A release line moves by a decision

| Component | Was | Is | Supported until |
|---|---|---|---|
| ClickHouse | 24.8 | 26.8.36.3, an LTS | 2027-08 |
| Redpanda | v24.2.20 | v26.2.6 | 2027-07-28 |
| PostgreSQL | 16.4 | 16.15 | 2028-11 |
| Prometheus | v3.5.0 | v3.13.5, an LTS | 2027-07-31 |
| Go build image | 1.26.10-bookworm | 1.26.10-trixie | the agent's image, Debian's stable |

The integration suite passed the new versions at the first attempt, 131 of 131, and
that proved nothing about what had changed. Comparing every default of the old and new
versions found what it could not:

**ClickHouse 26.2 turned `async_insert` on by default.** Every writer silently became an
asynchronous insert. At the writer's default batch that is 63,000 rows a second where a
synchronous insert writes 207,000, and worse the smaller the batch: 16 inserts a second
against 200, as each waits for the queue's 50 ms. It also broke
[ADR 34](0034-a-stored-event-is-named-by-the-agent-that-sent-it.md) in the one place its
test looked away: an insert queued when the names are exchanged holds no table, so the
store refuses it (`TABLE_UUID_MISMATCH`, or an unknown table), and a writer that was
promised it could keep writing retried instead. `connect` now states `async_insert = 0`
for every connection, because a batch is already a batch in the writers, the log behind
them is the buffer, and a default of the store must not decide the write path. The test
of the rebuild no longer ignores a refused write: it fails five times of five without
the setting and passes twenty of twenty with it. No acknowledged row was lost either way.

**Redpanda 26.2 refuses a record more than an hour ahead of the broker**
(`log_message_timestamp_after_max_ms`), where 24.2 only warned at two. A record's
timestamp is the clock of the process publishing it, never an agent's, so only a host
whose clock is an hour wrong reaches this, and it answers `503` and is retried.
Nothing else that changed matters here: `write.caching` is on by default in both, as
[ADR 41](0041-production-is-the-default-and-development-is-declared.md) records, and
`min.insync.replicas` is still not reported.

So Dependabot proposes patches only within a line, and a line moves by hand: **compare
`system.settings`, `system.merge_tree_settings` and `rpk cluster config export --all`
of both versions before trusting a green suite.** Redpanda has a further reason:
it climbs one feature release at a time.

### One toolchain

`go.mod` is the only place that names Go, at `go1.26.10` in the three repositories:
`setup-go` reads it, and `TestOneToolchainBuildsTheModule` holds `deploy/Dockerfile` to
it, as the agent's test holds the image that rebuilds its package. The backend's `go`
line rose to 1.26.0 because `x/crypto` v0.56.0 and later require it, and the line was
out of support anyway.

### What is scanned, and what stops a merge

| Tool | Runs | Stops a merge |
|---|---|---|
| `govulncheck -scan package` | every pull request, daily | yes |
| `gosec` | every pull request, daily | yes |
| CodeQL `security-extended` | every pull request, weekly | if the analysis fails; alerts go to the Security tab |
| Grype on the 15 component images | every image build, daily | on a fixable high or critical |
| Grype on third-party images | daily | no, it reports |

**`govulncheck` runs at package level**, stricter than the symbol level before it: nothing
this module links may be known vulnerable, reached or not. Module level, which the
card asked for, cannot be clean: `GO-2026-5932` says `x/crypto/openpgp` is unmaintained,
no release fixes it, and `x/crypto` stays in the graph for the SCRAM of the backbone
client. Nothing here imports that package, and the difference between the two levels
is exactly code that is not compiled in, so package level is the claim worth keeping.

**`gosec` excludes by path, not by rule, where it can.** `.gosec.json` names the files
each finding was read in, so the same finding anywhere else stops a merge. Two rules are
off everywhere. G115 flags every narrowing conversion whatever bounds it: all 146 in the
backend and the agent were read, and every value from outside is bounded by a validator
first. CodeQL's `go/incorrect-integer-conversion` follows a parsed integer to its
conversion, which is the case that matters. In the agent, G104 flags `Close` on paths
already failing and writes to a `bufio.Writer`, whose error `Flush` reports.

**Grype and not Trivy,** because Trivy's own action and releases were compromised in
March 2026 (CVE-2026-33634, in CISA's catalogue). It runs from `compose.test.yaml` like
`promtool`, by digest, as the caller, with no capability and no Docker socket, which
would be root: it reads an archive. It was proven able to refuse: a stripped binary in
`FROM scratch`, built with Go 1.25.5 and an old `x/net`, exits 2. Third-party images
report rather than refuse, since a finding there is the upstream's to fix and a gate
would stop every pull request of a project that can do nothing about it.

### A release tag is signed, and stays where it was published

A release is tagged with an SSH key, in each repository with `tag.gpgSign` set, and
verified before it is pushed:

```bash
git tag -m v1.2.3 v1.2.3 && make verify-tag TAG=v1.2.3 && git push origin v1.2.3
```

The order matters. On git 2.43, Ubuntu 24.04's, a signature that fails, such as a
mistyped passphrase, prints an error, exits 0 and leaves an unsigned tag, and a pushed
tag can neither move nor go. After the push, `.github/workflows/tags.yml`
(the first job of the agent's `release.yml`, which everything else waits for) runs
`make verify-tag` again. Whoever may sign is read from `.github/allowed_signers` **on `main`**,
never from the tag's own tree, or a tag could vouch for itself. An unsigned tag, a
lightweight tag, a stranger's key and a tag adding its own key were all refused in a
scratch repository. `.github/rulesets/tags.json` forbids moving or deleting `v*`, which
is what the module proxy already assumes.

GitHub cannot refuse the push itself: what its rulesets require signed is a commit, and
what a tag points at is a merge commit GitHub signed. So a forged tag can exist, and what
it cannot do is pass CI or become an agent release. This is a key a person holds, beside
the agent's keyless attestation of what the workflow built: the attestation says a
workflow built a package, and the tag says somebody decided to release it.

## Consequences

- **A development volume from before this does not start.** Redpanda v26.2.6 aborts on a
  v24.2 data directory (`incompatible logical version 13 to logical version 19`), so the
  backbone of an existing development stack has to be dropped once, `make down` being
  the way. ClickHouse and PostgreSQL read theirs, which was tested on copies. No
  production data exists; were there any, it would climb every feature release.
- **The Security tab starts with 29 alerts, none a defect.** 27 in the backend and 2 in
  the agent, read one by one: 15 conversions bounded by the configuration parser or
  `MaxCount`, 10 log lines through `slog`, which escapes them, a pass-through of protobuf
  bytes, a sum of bounded lengths, and two `uint32` held in an `int` on 64 bits.
- **A third-party image can hold what its upstream has not fixed.** Today Redpanda's
  holds `libbrotli1` with CVE-2026-111497, critical and exploited, as a dependency of
  `curl`; the broker does not load it, and no newer image exists. Prometheus's holds a
  `grpc` that only `promtool` carries here, and Grype's own was built with Go 1.26.8.
- **`main` can stop for reasons outside it.** With no bypass, an outage of Docker Hub
  stops every merge, and the image pull retries for that reason. A new advisory stops
  every pull request but the one that fixes it, which is what was asked for.
- **Dependabot sees neither the toolchain nor the scanners.** A new Go patch reaches the
  Dockerfile as a pull request that `TestOneToolchainBuildsTheModule` fails until
  `go.mod` follows, which is the reminder. The scanners are pinned in each `Makefile`.
- **One toolchain is a state, not an invariant, across repositories.** Each repository
  holds itself to `go.mod`, and comparing them would need one to read another.
- **The release key is one file on one machine, and it stays out of `~/.ssh`.** It has a
  passphrase, so neither a stolen GitHub token nor a process on that machine can sign
  with it, and a release takes a person at a terminal. GNOME's SSH agent offers whatever
  it finds in `~/.ssh` and holds a key open in memory once it is used, until logout,
  which would undo the passphrase; a key elsewhere is read from its file, asks for the
  passphrase and leaves nothing behind. A lost key is replaced by a pull request changing
  its line in `allowed_signers`, and tags signed before it stay as they are, since a tag
  is verified when it is pushed.

## Alternatives rejected

- **`strict_required_status_checks_policy`.** It would make the merged tree exactly the
  tree that was checked, and is the stronger rule. But merging one branch of a stack
  would leave every branch above it out of date, each to be updated and run again: 7
  minutes a branch here, 30 in the agent. Since every commit on `main` now finishes its
  CI, two changes that break only together are found minutes after the merge rather than
  before it. It is one word in the ruleset if Dependabot's volume changes that.
- **One aggregate job as the only required check.** It survives a renamed job, and
  `needs` would have to be tested against the job list just the same. Listing each job
  shows each as required, and the rule rarely changes.
- **Renovate.** It would see more, and it is one more application with write access to
  a security product. Dependabot is GitHub's own and needs nothing installed.
- **`code_scanning` merge protection.** It belongs here once it has been seen working
  with a stack: a pull request retargeted to `main` runs no new analysis, and a rule that
  waits for one would strand it. CodeQL's job is required; its alerts do not stop a merge.
- **A list of accepted advisories at module level.** It would keep a file true by hand
  to say what package level already proves.
- **Signed commits on `main`.** GitHub signs its merge commits, and requiring it of
  branches would say who pushed them, which the pull request already records.
