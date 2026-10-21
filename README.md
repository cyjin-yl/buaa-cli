# buaa-cli

`buaa-cli` is a Rust command-line toolkit for BUAA workflows. The Cargo package is
`buaa-cli`; the executable is `buaa`. Commands use JSON or NDJSON on standard
input/output and fail closed when a source, contract, or safety prerequisite is
missing.

This is an offline-first project, not an all-service campus client. The current
implementation includes local calculators and bounded, cache-first read slices;
network observations are deliberately opt-in and remain subject to the shared
governor.

## Status boundary

Implemented or available as bounded slices:

- **Offline tools:** timed input replay, marks/GPA and local baselines, graduation-credit reference checks, API/schema drift reports, timetable-to-ICS conversion, and physics data reduction.
- **Cache-first reads:** exact-URL archive lookup/capture, the pinned Fengrubei release, the official organization directory, selected announcement/document sources, public SPOC surface metadata, and authorized local recording-catalog search.
- **Gateway client:** usage, login/logout planning, and recovery contracts are implemented and loopback-tested; live campus compatibility and account operations are **unverified**.

These slices do not complete the broader catalog. Full adapter coverage, general safe raw-response fallback, and end-to-end online verification remain unfinished. No campus authentication, campus mutation, live grade read, remote recording retrieval, all-college announcement history, or authenticated SPOC course/material adapter is claimed. Native subtitle normalization is not player delivery or synchronized playback.

The machine-readable status projection is [`acceptance.json`](acceptance.json). See [`docs/STATUS.md`](docs/STATUS.md) for evidence and blockers; neither links nor a status entry are a substitute for an implemented command.

## Build and discover

Use Rust 1.89 or newer on Linux. Dependency fetching is public and does not require campus access. If dependencies are not already cached, fetch them once, then build offline:

```sh
cargo fetch --locked
cargo build --locked --offline
./target/debug/buaa help
./target/debug/buaa capabilities
./target/debug/buaa schema
```

`help` describes the command surface, `capabilities` emits the acceptance manifest, and `schema` emits the input/output contracts and error codes. Pending or deferred capabilities are not available commands. The public [devcontainer definition](.devcontainer/README.md) describes a pinned, credential-free environment; the definition alone does not prove a successful image build.

## Command overview

| Surface | Commands | Boundary |
| --- | --- | --- |
| Timed input | `timed-input [--raw] [--dry-run]` | Reads `[seconds]text` from stdin; no program is executed by the CLI. |
| Archive | `archive lookup\|capture [--online\|--refresh]` | Exact URL/date-bounded CDX and timestamped replay; it never contacts the original campus URL. See [`docs/ARCHIVE.md`](docs/ARCHIVE.md). |
| Template | `fengrubei info\|fetch`; `fengrubei fetch --online` | One pinned upstream archive; it is not an official/current-format guarantee. See [`docs/FENGRUBEI.md`](docs/FENGRUBEI.md). |
| Marks and credits | `marks gpa`; `marks baseline save\|show <absolute-path>`; `credits calculate\|school6` | Offline, operator-supplied policies and course facts; no grades are fetched and graduation is not certified. |
| Local data tools | `recordings search`; `drift check`; `timetable ics`; `physics type-a\|fit\|pendulum` | Read-only local/catalog or stdin-driven processing. Recording results do not verify media rights or fetch objects. |
| Directory | `organizations list [--online\|--refresh]` | Reads one fixed official teaching/research directory; it does not crawl linked colleges. See [`docs/ORGANIZATIONS.md`](docs/ORGANIZATIONS.md). |
| Announcements | `announcements list\|article\|document\|history`; `announcements college-source <college> [root\|notices\|public-notices]` | Selected source-bound pages and documents only; broader adapters, attachments, and history remain partial. |
| Public SPOC | `spoc surface [root\|entry]`; `spoc script` | Sanitized public-surface metadata only; this is not authenticated course/material access. See [`docs/SPOC.md`](docs/SPOC.md). |
| Gateway and governor | `gateway usage` and explicit operation flows; `governor boot-review-plan\|boot-review-commit --offline` | Cache-first gateway usage and local safety flows; no live account operation is claimed. See [`docs/GATEWAY.md`](docs/GATEWAY.md). |
| Defect reporting | `report` | Explicitly writes a GitHub Issue from operator-sanitized input through an installed, authenticated `gh`; authentication failures and uncertain writer outcomes remain explicit. The command does not redact private content: never attach credentials or raw private responses. |

For exact argument shapes, supported college values, output fields, and bounds,
use `./target/debug/buaa schema` rather than relying on a summary table.

## Examples

### Local timed input

```sh
printf '[0]first\n[0.25]second\n' | ./target/debug/buaa timed-input
printf '[1.0]1-FROM-1-TO-2\n[2.0]2-FROM-1-TO-3\n' | ./target/debug/buaa timed-input --raw | your-local-program
printf '[86400]tomorrow\n' | ./target/debug/buaa timed-input --dry-run
```

The default output is flushed NDJSON. `--raw` emits newline-delimited text,
not JSON; `--dry-run` validates and emits the schedule without sleeping. These
options are mutually exclusive, and all input is validated before output.

### Cache-only reads

An offline miss is unavailable, not an empty success. These examples do not
make network requests:

```sh
# Synthetic example: default cache-only lookup, no network request.
printf '%s\n' '{"url":"https://college.example/notice/42.html","limit":100}' | ./target/debug/buaa archive lookup

# Private cache only; no network request.
./target/debug/buaa organizations list

# Cache-only selected source and bound non-personal policy; no network.
printf '%s\n' '{"college":"ic","since":"2026-09-01","match":"评审方案"}' | ./target/debug/buaa announcements list
printf '%s\n' '{"url":"https://ic.buaa.edu.cn/info/1042/4815.htm"}' | ./target/debug/buaa announcements article

# Private cache only; no network request.
./target/debug/buaa spoc surface
printf '%s' '{"url":"https://spoc.buaa.edu.cn/spocnew/js/app.a7c0879c.js"}' | ./target/debug/buaa spoc script
```

The cache-first contracts, source binding, provenance, and privacy limits are
documented in [`docs/ARCHIVE.md`](docs/ARCHIVE.md),
[`docs/ORGANIZATIONS.md`](docs/ORGANIZATIONS.md), and [`docs/SPOC.md`](docs/SPOC.md).

### Local calculators and catalog search

```sh
printf '%s\n' '{"major":"会计学","selected":["健康经济学"]}' | ./target/debug/buaa credits calculate
printf '%s\n' '{"cohort":"2020","courses":[{"id":"example","name":"Synthetic elective","credits":2,"category":"general_major","passed":true,"qualifications":{"english":true}}]}' | ./target/debug/buaa credits school6
printf '%s\n' '{"baseline":{"v":"s"},"candidate":{"v":5}}' | ./target/debug/buaa drift check
printf '%s\n' '{"catalog":"/private/catalog.sqlite","query":"linear algebra","authorized":true,"limit":20}' | ./target/debug/buaa recordings search
```

The catalog path is an example and must refer to an existing SQLite database the
operator is authorized to read. `authorized: true` is an attestation, not proof
of media rights. See [`docs/RECORDINGS.md`](docs/RECORDINGS.md) for the local
catalog contract.

### Pinned template and gateway usage

```sh
./target/debug/buaa fengrubei info
printf '%s\n' '{"output":"/home/operator/private/template-v1.0.3.zip"}' | ./target/debug/buaa fengrubei fetch
./target/debug/buaa gateway usage
```

Template fetching is cache-only unless `--online` is explicit. The destination
must be a new absolute path inside an existing owner-controlled, symlink-free,
non-world-writable parent. Gateway login and logout require separate typed
stdin flows; credentials never belong in arguments, logs, fixtures, or this
repository. Read [`docs/FENGRUBEI.md`](docs/FENGRUBEI.md) and
[`docs/GATEWAY.md`](docs/GATEWAY.md) before using those flows.

## Network and account safety

- Source-reading commands default to local cache/offline mode. `--online` or `--refresh` is an explicit opt-in for archive, organization, announcement, and SPOC reads; `fengrubei fetch --online` is explicit; gateway operations have their own explicit online flags. `report` is a separate explicit GitHub Issue-writing operation, not a campus read.
- All governed reads use the process-shared account governor through response processing and private persistence. Worktrees must not create independent limiters or account aliases.
- TLS validation, allowlists, bounded responses, cache integrity checks, and source/provenance checks apply before data is accepted. There is no automatic authentication refresh/retry, challenge bypass, or campus mutation in this development scope.
- Keep credentials, private cache files, raw campus responses, and personal media outside the repository. A successful cache read does not prove current service availability or rights.

The detailed gateway contract is in [`docs/GATEWAY.md`](docs/GATEWAY.md); public
source and archive limits are in their linked documents above. Do not infer a
new adapter or endpoint from a catalog link.

## Documentation

- [Documentation landing page](docs/index.html) — public command and safety overview.
- [Current evidence and blockers](docs/STATUS.md) — dated implementation boundaries, not a receipt ledger to duplicate here.
- [Full acceptance matrix](acceptance.json) — machine-readable capability status.
- [Upstream and license references](docs/REFERENCES.md) — research boundaries and licensing notes.
- [Changelog](CHANGELOG.md).
- [Contributor and maintenance rules](AGENTS.md) — including review, reporting, and gh-stack workflow; those operational instructions do not belong in this README.

License: [MIT](LICENSE).
