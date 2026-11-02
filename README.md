# buaa-cli

`buaa-cli` is a Rust command-line toolkit for BUAA workflows. The Cargo package is
`buaa-cli`; the executable is `buaa`. Commands use JSON or NDJSON on standard
input/output and fail closed when a source, contract, or safety prerequisite is
missing.

This is an offline-first project, not an all-service campus client. The current
implementation includes local calculators and bounded, cache-first read slices;
network observations are deliberately opt-in and remain subject to the shared
governor.

## Repository and publication boundary

Development uses the private [Gitea primary](https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli).
Its existing daily synchronization considers **every branch and tag** for
non-force publication to the public GitHub downstream. A successful sync can
therefore publish pushed drafts and checkpoints as well as `main`; deletion
from Gitea does not automatically delete a downstream ref. Treat every push
as public publication and never commit credentials, private responses, or
other non-public material. A private Gitea visibility setting is not an
exclusion from this synchronization. Removing a published downstream ref
requires a separately authorized GitHub-side action; deletion does not prove
that already distributed content has been erased.

Gitea and GitHub pull requests have separate numbers, reviews and checks.
An approval or successful check on one host is not evidence of an approval or
check on the other. Use `gh stack` for the ordered local branches required by
the contributor contract, and review the Gitea pull-request chain on the
primary. A Gitea draft does not itself register a GitHub native stack or
authorize a merge. Do not merge the GitHub downstream as a substitute for
integrating the primary; integrate on Gitea only after the exact-head review
and acceptance gates are satisfied.

## Status boundary

Implemented or available as bounded slices:

- **Offline tools:** timed input replay, marks/GPA and local baselines, graduation-credit reference checks, API/schema drift reports, timetable-to-ICS conversion, and physics data reduction.
- **Cache-first reads:** exact-URL archive lookup/capture, the pinned Fengrubei release, the official organization directory, selected announcement/document sources, public SPOC surface metadata, and authorized local recording-catalog search.
- **Gateway client:** usage, login/logout planning, and recovery contracts are implemented and loopback-tested; live campus compatibility and account operations are **unverified**.

These slices do not complete the broader catalog. Full adapter coverage, general safe raw-response fallback, and end-to-end online verification remain unfinished. Dated authorized session and recording observations in the status evidence are bounded reads, not general campus compatibility. Campus mutation, live grade reads, all-college announcement history, and authenticated SPOC course/material coverage remain unverified. Native subtitle normalization is not player delivery or synchronized playback.

The machine-readable status projection is [`acceptance.json`](acceptance.json). See [`docs/STATUS.md`](docs/STATUS.md) for evidence and blockers; neither links nor a status entry are a substitute for an implemented command.

CAS development notes are archived in
[`docs/CAS-LOGIN-PROTOCOL.md`](docs/CAS-LOGIN-PROTOCOL.md), with the bounded
BUAA observation in
[`docs/SSO-LOGIN-PROTOCOL.md`](docs/SSO-LOGIN-PROTOCOL.md). Browser observations
do not establish a CLI session or prove the cause of a callback error.

## Build and discover

Use Rust 1.89 or newer on Linux. Dependency fetching is public and does not require campus access. If dependencies are not already cached, fetch them once, then build offline:

```sh
cargo fetch --locked
cargo build --locked --offline
./target/debug/buaa help
./target/debug/buaa capabilities
./target/debug/buaa schema
```

`help` describes the command surface, `capabilities` emits the acceptance manifest, and `schema` emits the input/output contracts and error codes. Pending or deferred capabilities are incomplete; some expose bounded partial or blocked commands, which do not establish acceptance. The public [devcontainer definition](.devcontainer/README.md) describes a pinned, credential-free environment; the definition alone does not prove a successful image build.

## Command overview

| Surface | Commands | Boundary |
| --- | --- | --- |
| Timed input | `timed-input [--raw] [--dry-run]` | Reads `[seconds]text` from stdin; no program is executed by the CLI. |
| Archive | `archive lookup\|capture [--online\|--refresh]` | Exact URL/date-bounded CDX and timestamped replay; it never contacts the original campus URL. See [`docs/ARCHIVE.md`](docs/ARCHIVE.md). |
| Template | `fengrubei info\|fetch`; `fengrubei fetch --online` | One pinned upstream archive; it is not an official/current-format guarantee. See [`docs/FENGRUBEI.md`](docs/FENGRUBEI.md). |
| Marks and credits | `marks gpa`; `marks baseline save\|show <absolute-path>`; `credits calculate\|school6` | Offline, operator-supplied policies and course facts; no grades are fetched and graduation is not certified. |
| Local data tools | `recordings search`; `drift check`; `timetable ics`; `physics type-a\|fit\|pendulum` | Read-only local/catalog or stdin-driven processing. Recording results do not verify media rights or fetch objects. |
| Local replay | `recordings replay` | Explicitly authorized local media through installed mpv/VLC, with initial seek, optional SRT/VTT and bounded stop. Normal A/V output is default; headless mode is explicit. Remote/live playback is not implemented. See [`docs/RECORDINGS.md`](docs/RECORDINGS.md#bounded-local-replay). |
| Directory | `organizations list [--online\|--refresh]` | Reads one fixed official teaching/research directory; it does not crawl linked colleges. See [`docs/ORGANIZATIONS.md`](docs/ORGANIZATIONS.md). |
| Announcements | `announcements list\|article\|document\|history`; `announcements college-source <college> [root\|notices\|public-notices]` | Selected source-bound pages and documents only; broader adapters, attachments, and history remain partial. |
| Public SPOC | `spoc surface [root\|entry]`; `spoc script` | Sanitized public-surface metadata only; this is not authenticated course/material access. See [`docs/SPOC.md`](docs/SPOC.md). |
| Smart reads | `smart [--online]`; `smart session [--online]` | Existing cookie/token reads, or one explicit in-memory CAS login followed by one classrooms/library read. Strict-TLS loopback and local CLI proof only; no live campus acceptance, persistence, automatic refresh or attendance mutation. |
| iHome appeals | `ihome list\|detail [--online]`; `ihome session [--online]` | Caller-token reads, or one explicit in-memory CAS login followed by one list page/detail. No session persistence, retry or attachment fetching. Offline/native proof only; no live campus acceptance. |
| Course selection | `enrol [--online]` | Separate historical IEAS local list/preview and modern yjsxk existing-session selected-record read. No login, enrolment, withdrawal or authoritative postcondition. See the application boundary below. |
| Aerospace study | `aerospace materials\|search\|fetch\|practice [--online]` | Pinned community inventory; only the exact reviewed root README and LICENSE are retrievable. Question bank, question images, fonts, implementation and aliases remain excluded. Practice uses authorized local input only. |
| Contribution discovery | `contribution scan` | Protected-stdin GitHub or fixed-primary Gitea read. `online: true` is the explicit network gate; no issue claim, PR creation, merge or campus permission is granted. |
| Gateway and governor | `gateway usage` and explicit operation flows; `governor boot-review-plan\|boot-review-commit --offline` | Cache-first gateway usage and local safety flows; no live account operation is claimed. See [`docs/GATEWAY.md`](docs/GATEWAY.md). |
| Defect reporting | `report` | Explicitly writes a GitHub Issue from operator-sanitized input through an installed, authenticated `gh`; authentication failures and uncertain writer outcomes remain explicit. The command does not redact private content: never attach credentials or raw private responses. |

For exact argument shapes, supported college values, output fields, and bounds,
use `./target/debug/buaa schema` rather than relying on a summary table.

### Explicit Smart session

`smart session --online` accepts JSON only through protected stdin: `authorized`,
`username`, `password`, `intent` and `read`. The intent must be exactly
`LOGIN <username> smart <service>`, where the service is `classrooms` or `library`.
The object-only `read` selects an enabled flag and either classrooms'
`campus_id`/`date`, or a library `premises`, `areas`, `times` or `seats` query.
The complete contracts are `commands.smart.session.input` and `.output` in
`buaa schema`. Caller-supplied cookies, tokens, CAS values and write operations
are not accepted in this session read. The original `smart` cookie/token
contract remains separate; its obsolete caller-supplied library login is removed.

A disabled read performs no network or account-state I/O. An enabled read
requires explicit authorization, the exact intent, a valid local query and
`--online` before transport is opened. One existing Authentication lease spans
the selected CAS flow, the library's one-time exchange when selected, and the
single business read. Cookies and tokens remain private to the invocation;
there is no stored-session reuse, automatic login refresh or retry. Challenges,
deferrals and unconfirmed authentication stop the flow. A complete HTTP failure
is not presented as a password verdict. Authentication responses are never raw
read evidence; credential echoes in the final response are withheld.

### Source-faithful iHome reads

`ihome list`, `ihome detail` and `ihome session` accept JSON only through
stdin; `buaa schema` publishes all three contracts. Legacy list/detail accept
a caller-supplied bearer. Their optional `token_source` remains a caller
declaration, not proof of token acquisition or current lifetime.

`ihome session [--online]` requires `authorized: true`, `username`, `password`,
the exact intent `LOGIN <username> ihome`, and a `read` object selecting
`operation: "list"` or `"detail"` with `enabled: true`. A list selects one page
(`limit` 1–100, default 20; `page` defaults to 1); detail requires an unsigned
`id`. Valid disabled reads check shape but not credential values or permission,
and perform no account-state or network I/O. Enabled reads validate locally
before constructing the client. Caller tokens, cookies, URLs and writes are
not session inputs.

One existing Authentication lease covers the fixed CAS flow and exactly one
HTTPS business GET. The exact reviewed HTTP callback is upgraded to HTTPS;
the terminal `/web/` fragment token is consumed without fetching its URL.
No authentication response, token or read response is persisted or cached;
there is no automatic pagination, refresh or retry. Final responses are checked
against all held credential material before projection or safe fallback.
A token or positive public listing does not establish account identity or
full rights. Strict-TLS loopback and actual local CLI proof are not live-campus
acceptance.

Records without a title remain untitled; supplied titles and dates are copied,
not reconstructed. HTTP 200 alone is not business success: numeric `code=20000`
and Boolean `success=true` are required. Negative or unknown business envelopes
return degraded evidence with safe original bytes rather than an empty result.

Pagination must match the requested page/limit and declared total/last page.
Missing or inconsistent metadata, repeated IDs, changing totals and later read
failures preserve valid records but stop traversal without advancing a cursor.
A consistent bounded window may return `has_more`; advance incremental cursors
only after completing its traversal. Unknown idle-window and attachment
contracts remain unknown; declared URLs are neither fetched nor a verified
complete attachment inventory. No current-campus iHome acceptance is claimed.

Issued response cookies are not adopted or transmitted. Their values remain in
a bounded, invocation-only privacy guard across the whole legacy list traversal,
including later fresh and cached bodies and MIME metadata. Cookie-issuing
responses are not cached. Inspection exhaustion withholds evidence rather than
exporting a reversible fallback; independently observed challenge, rejection
and Retry-After facts still govern settlement.

### Separate course-selection applications

IEAS is the default application. Its local preview is not a live application
binding: historical academic-year `pageXnxq` and local `page_xnxq` spellings are
not interchangeable. A current independently trusted strict-HTTPS IEAS origin,
authenticated account/term scope and complete postcondition remain missing.
Online IEAS operations and library postcondition verification remain blocked;
supplying a synthetic Session does not establish those facts.

The separate protected-stdin contract for a yjsxk observation is
`application: "yjsxk"`, `operation: "selected"`, an exact five-digit `xnxqdm`,
`authorized: true` and an existing `session_cookie`. The command must also have
`--online`. Obtain the complete object-only contract from `buaa schema`; do not
put the cookie in argv, shell history, examples or the repository.

This reader makes one fixed HTTPS GET, without proxies, login, redirects,
retry, polling, cookie adoption or persistence. The requested term filters
native `XNXQDM`; `BJDM`, selected-row `WID` and `YYZ` keep separate roles.
Source order and duplicate rows remain intact, and missing facts remain null.
Neither an empty list nor an observed row establishes authenticated account
identity, complete selection, withdrawal, current rights or a final
postcondition. No current authenticated yjsxk deployment acceptance is claimed.
Enrolment, withdrawal and wish-value writes remain blocked.

### Forge-specific contribution discovery

`contribution scan` defaults to GitHub. Selecting `provider: "gitea"` admits
only `repository: "ezra/buaa-cli"` on the fixed HTTPS primary; it requires
`gitea_token` through protected JSON stdin. The GitHub provider uses
`github_token`; cross-provider credentials are refused. Offline scans perform
no requests or credential lookup. Online reads require `online: true` in that
same stdin object, not a command-line token.

Gitea issues and timeline events are enumerated to a real empty page, within
the published bounds. `X-Total-Count` detects disagreement, not termination.
Comments are fetched once and require a matching count and unique identities.
Unknown, foreign, contradictory or incomplete PR/claim evidence excludes an
issue rather than making it eligible. Discovery is a point-in-time observation:
refresh live permission, discussion, claim and PR state before any separately
authorized write. Gitea evidence does not create a GitHub stack or transfer
approvals between hosts.

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
