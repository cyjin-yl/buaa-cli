# buaa-cli

`buaa-cli` is an agent-facing Rust CLI. Implemented offline slices include timed-input, archive lookup/capture, policy-provenanced marks/GPA calculation, scoped credit calculation, pinned Fengrubei template retrieval, local recording-catalog search, official organization-directory parsing, and news-index parsing. A governed two-page live Internet Archive CDX read was manually observed; this does not establish complete history or live Memento replay. Gateway workflows remain live-unverified, archive reads default to cache, and no campus authentication, mutation, or origin-host request was performed. Other acceptance items remain partial, pending, or blocked.

## Build and discover

```sh
cargo build --locked --offline
./target/debug/buaa help
./target/debug/buaa capabilities
./target/debug/buaa schema
```

The initial dependency fetch requires crates.io access, not campus access. Rust 1.89 or newer is required; Linux is the current governor target.

For a clean development environment, use the [public devcontainer definition](.devcontainer/README.md). Official Rust 1.98.1 and Node 22.23.2 images are digest-pinned; OMP 18.2.6 is checksum-verified. No private HOME, model configuration, GitHub hosts, SSH or Life files enter the build. Full image execution remains unverified in this seat because no container builder is available.

## Timed input

Original local utility compatible with the documented `[seconds]text` format from [TimeInput](https://github.com/dhy2000/TimeInput). No upstream source was copied. This tool is for local debugging, not inclusion in submitted coursework.

```sh
printf '[0]first\n[0.25]second\n' | ./target/debug/buaa timed-input
printf '[1.0]1-FROM-1-TO-2\n[2.0]2-FROM-1-TO-3\n' | ./target/debug/buaa timed-input --raw | your-local-program
printf '[86400]tomorrow\n' | ./target/debug/buaa timed-input --dry-run
```

Default stdout is flushed NDJSON:

```json
{"type":"timed_input","sequence":1,"at_ns":0,"text":"first"}
```

`--raw` explicitly selects newline-delimited text for a pipe; it is not JSON. `--dry-run` validates and emits the same NDJSON schedule without sleeping. These options cannot be combined. No program is executed by the CLI itself. The clock starts after all stdin has been read and validated; close stdin to start replay. Uses monotonic absolute deadlines; operating-system scheduling or a slow consumer may delay delivery. EOF follows the final event when the CLI exits.

Grammar: nonnegative integer seconds with optional 1–9 decimal places, maximum 86400 seconds inclusive; nondecreasing timestamps, stable ties; 100000 rows and 8 MiB input maximum. LF/CRLF, optional final newline, empty text and empty schedules are supported. Tabs/spaces are preserved; other control characters and blank rows are rejected. Invalid late rows cause **zero output**, including raw mode. Errors never echo input or arguments. Successful replay intentionally returns supplied text: do not feed credentials into a text-replay utility.

Errors are JSON on stderr with `schema_version`, `error` and sanitized `message`. Exit codes: 2 invalid input, 3 unsupported, 4 safety/auth-latched, 5 permission, 7 unavailable I/O, 8 rate-limited and 9 immutable-content conflict. Gateway authentication requires an explicit typed `resume-auth` before exactly one online login flow; there is no automatic refresh/retry. A replay I/O failure may leave earlier events delivered; do not blindly restart a pipe into a side-effectful program.

## Historical archive reads

`buaa archive lookup` accepts an exact original URL, optional inclusive UTC date bounds and a continuation cursor. `buaa archive capture` retrieves an exact timestamped replay with matching Memento attribution, original-byte SHA-256 and base64 bytes. Publication dates stay unknown; capture time is not publication time, and gaps are never reconstructed.

```sh
# Synthetic example: default cache-only lookup, no network request.
printf '%s\n' '{"url":"https://college.example/notice/42.html","limit":100}' | ./target/debug/buaa archive lookup
```

Use `--online` only for authorized archive reads on cache misses, or `--refresh` for conditional revalidation. Robots rules, the shared governor, fixed HTTPS routes and immutable-original conflict checks apply. Rejected provenance never becomes an immutable cache entry. See [archive contracts and examples](docs/ARCHIVE.md); live service availability remains unverified.

The [upstream contract and license assessment](docs/REFERENCES.md) records inspected source revisions, incompatible safety defaults that are not adopted, licensing boundaries and remaining integration gaps. Reference code is not permission or evidence of a working live campus adapter.
## Pinned Fengrubei template access

`buaa fengrubei info` reports an immutable upstream release reference, LPPL license, byte/hash integrity and caveats without network access. `fengrubei fetch` copies only the verified original ZIP from a private cache to an explicit new absolute path.

```sh
./target/debug/buaa fengrubei info
printf '%s\n' '{"output":"/home/operator/private/template-v1.0.3.zip"}' | ./target/debug/buaa fengrubei fetch
```

Use `fetch --online` only to permit a governed public download on cache miss. The output parent must already exist, be owned by the current user, reject group/other writes, and contain no symlink path components. The client checks robots on both GitHub hosts, validates one explicit redirect, streams and verifies 52,816,733 bytes, and never unpacks, executes, compiles or overwrites. See [license, font and format caveats](docs/FENGRUBEI.md). The community release is not an official/current-format guarantee.

## Marks/GPA (offline)

`buaa marks gpa` computes a weighted GPA from a caller-supplied, provenanced policy (table bands or formula) and course list, with per-course pass flags and an optional structured diff against an inline baseline. No campus grades are fetched. A schema-published arithmetic ceiling bounds both individual and aggregate course credits; overflow is rejected rather than serialized as a misleading `null`.

```sh
printf '%s\n' '{"policy":{"kind":"table","id":"p1","source":"<published-url>","pass_min":60,"bands":[...]},"courses":[{"name":"...","score":92,"credit":4.0}]}' | ./target/debug/buaa marks gpa
```

`buaa marks baseline save|show <absolute-path>` persists an idempotent local `gpa_baseline` snapshot. The parent directory must already exist, be owned by the current user, and not be group/other-writable; symlink components are rejected. Baseline files are regular owner-controlled `0600` files. Legacy baselines with broader permissions must be restricted before use. Identical re-saves report `unchanged` without rewriting. The stored baseline can be pasted as the `baseline` field of `marks gpa` to produce added/removed/changed and GPA-delta. The live campus grades adapter is a separate blocked capability; see `acceptance.json`.

## Graduation credits (offline)

`buaa credits calculate` implements the sourced School-8 2020 general-major calculation. `major` must match a declared non-general major tag from the catalog. Same-name catalog rows are accepted only when credit, displayed metadata and classification for that major agree; conflicting identities return `invalid_input`. Other cohorts/programs remain pending evidence.

```sh
printf '%s\n' '{"major":"会计学","selected":["健康经济学"]}' | ./target/debug/buaa credits calculate
```

## Local recording segment lookup
`buaa recordings search` performs read-only phrase lookup over an operator-authorized Life-compatible SQLite catalog. It returns nullable timing and separate catalog-reported original/derived descriptors and linking hashes. It does not fetch objects or verify media rights; unknown ancestry stays explicit.
# Supply an existing local catalog you are authorized to read; this path is an example.
printf '%s\n' '{"catalog":"/private/catalog.sqlite","query":"linear algebra","authorized":true,"limit":20}' | ./target/debug/buaa recordings search
See [recording catalog contracts](docs/RECORDINGS.md) for cursor binding, FTS semantics, provenance limits, privacy and SQLite sidecar behavior. Remote storage retrieval, recording intake, audio repair and complete Life service integration are not implied by this local query command.

## Account safety

Archive and template network reads share the process-wide governor for request, bounded response processing and private atomic persistence. The archive adapter fetches no original campus URL; the template adapter permits only one pinned GitHub release and validated release-asset redirect. All future adapters/provider processes must share the same state domain and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, autonomous auth retry, CAPTCHA bypass or real development-time campus mutation is allowed.
## Governed campus gateway client
The gateway adapter implements fixed TLS usage, login and logout flows, but has only synthetic offline/loopback proof; **no real campus authentication, usage request or logout is authorized or claimed verified**.
# Cache only.
./target/debug/buaa gateway usage
# Deliberately arm one attempt, then submit credentials through bounded stdin once.
printf '%s\n' '{"intent":"RESUME GATEWAY AUTH"}' | ./target/debug/buaa gateway resume-auth
printf '%s\n' '{"username":"<stdin-only>","password":"<stdin-only>","ip":"10.0.0.2","ac_id":62,"intent":"LOGIN <stdin-only> 10.0.0.2"}' \
  | ./target/debug/buaa gateway login --online
The example values are placeholders. Login uses an explicit resume and typed intent. Logout is split into offline `logout-plan` and explicit `logout-commit --online`; successful plan hashes have private idempotency receipts. The CLI performs no HTTP AC discovery, interface/DNS probe, credential storage, password argument, automatic retry, invalid-certificate mode or challenge/security-notice bypass. See [gateway safety, usage and mutation contracts](docs/GATEWAY.md).
Archive and gateway requests share the process-wide governor through request, bounded response classification and private persistence. The archive adapter fetches no original campus URL; gateway egress is fixed to TLS-validated `gw.buaa.edu.cn` paths. All future adapters/provider processes must share the same state domain and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, automatic authentication retry, CAPTCHA bypass or development-time campus mutation is allowed.
## Authoritative organization directory
`buaa organizations list` returns every entry in the captured official BUAA `教学科研机构` document, including hidden source entries and explicit missing/non-HTTP links. It never invents a URL or silently upgrades HTTP links.
# Private cache only; no network request.
./target/debug/buaa organizations list
Use `--online` only for an authorized cache miss, or `--refresh` for conditional revalidation. Egress is limited to the official robots and directory URLs and shares the same process-wide governor. See [directory semantics and governed observation evidence](docs/ORGANIZATIONS.md) and the [sanitized 2026-09-20 snapshot](docs/data/organizations-2026-09-20.json). Announcement crawling remains separate.
`src/net.rs` implements allowlisted archive and official-directory GETs through `src/governor.rs`; the organization command fetches no linked college site, and the archive command fetches no original campus URL. All future adapters/provider processes must retain the same request lease through response validation and persistence, share one private state domain, and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, autonomous auth retry, CAPTCHA bypass or real development-time campus mutation is allowed.

The Linux governor uses `.buaa-cli-governor` beneath the effective UID's passwd home, ignoring HOME/XDG/worktree overrides. One permanent file lock spans the full request/body lifetime; private atomic state preserves minimum 5-second completion gaps, 15-minute background intervals, Retry-After and one-shot auth permission. Boot-time deadlines cannot be shortened by wall-clock changes. All processes using a campus account must share this OS identity and filesystem state; this is not a distributed cross-host governor.

Unknown request outcomes (including crash or failed outcome persistence), reboot/boot-ID mismatch and corrupt/missing history fail closed. Ordinary auth resume does **not** clear unknown outcomes or cooldowns. These conditions require offline operator review; no automatic reset/recovery command is provided. Local filesystem locking/fsync semantics and cooperating same-UID clients are required.

See [contributor rules](AGENTS.md), [observed blockers and source research](docs/STATUS.md), and `acceptance.json` for the full 74-entry catalog mapping, including historical entries and the excluded credential-stealing entry. Catalog links are not API implementations. School-specific credit policies and historical systems require explicit evidence, never guessed behavior.

## Feature acceptance matrix

This table projects `acceptance.json`; update both together. `implemented-offline` verifies a local feature/library; `implemented-offline-tested` verifies an adapter against offline HTTP fixtures, and `implemented-observed-read` additionally records a bounded public source observation. `partial-offline` means the offline engine/contract is complete while a live campus adapter remains blocked. `pending` means not implemented, `blocked` names a missing prerequisite, and `deferred` applies only to VPN.
This table projects `acceptance.json`; update both together. `implemented-offline` verifies a local feature/library; `implemented-offline-tested` verifies a real adapter against offline HTTP fixtures, while `partial-live-unverified` means code exists but the parent acceptance still lacks authorized live proof. `pending` means not implemented, `blocked` names a missing prerequisite, and `deferred` applies only to VPN.
This table projects `acceptance.json`; update both together. `implemented-offline` verifies a local feature/library; `implemented-offline-tested` verifies an adapter against offline HTTP fixtures, and `implemented-observed-read` additionally records a bounded authorized source observation. `pending` means not implemented, `blocked` names a missing prerequisite, and `deferred` applies only to VPN.

| ID | Capability | Status |
| --- | --- | --- |
| governor | Shared cross-process request safety | implemented-offline |
| gateway | Gateway login/logout/usage | partial-live-unverified |
| spoc | SPOC materials/video/PPT/subtitles | blocked |
| live | Classroom live replay/audio repair | blocked — requires scoped owner-approved read authorization, current endpoint/session contract, authorized inventory, and rights-cleared original/derivation ([issue #47](https://github.com/cyjin-yl/buaa-cli/issues/47)) |
| smart | Smart BUAA services | pending |
| enrol | Undergraduate/postgraduate course selection/drop | pending |
| evaluation | Teaching evaluations | pending |
| marks | Marks/GPA/change monitoring | partial-offline |
| timetable-ug | Undergraduate timetable/ICS | pending |
| timetable-pg | Postgraduate timetable/ICS | pending |
| checkin | Classroom QR/direct check-in | pending |
| boya | Boya browse/enrol/drop/check/status | pending |
| ihome | ihome announcements | pending |
| electricity | Electricity query/alerts | pending |
| physics-select | Physics experiment selection | pending |
| physics-data | Physics experiment data processing | pending |
| physics-reference | Physics reference access | pending |
| aerospace | Aerospace study/questions | pending |
| drive | AnyShare campus drive | pending |
| departments | Department material catalogs | pending |
| os-lab | Authorized OS-lab jumpserver | pending |
| coursegrading | CourseGrading submissions | pending |
| timed-input | Timed-input utility | implemented-offline |
| credits | School-specific graduation credits | partial-offline |
| shuttle | Shuttle tickets | pending |
| welearn | WE Learn materials/practice | pending |
| fengrubei | Fengrubei template access | implemented-observed-read |
| crater | Crater allocation/API/SSH | blocked |
| organizations | Authoritative college/institute directory | implemented-observed-read |
| announcements | College current/historical announcements | partial-offline |
| archive | CDX/Memento historical lookup | implemented-offline-tested |
| recordings | Historical recordings/transcript segments | partial: local catalog search; remote media pending |
| life | Life external object storage/catalog | partial: read-only catalog profile; object retrieval pending |
| skills-fs | skills-fs HTTP provider | blocked |
| contribution | Governed autonomous contribution | pending |
| drift | Read-only API/schema drift detection | pending |
| publication | GitHub repository and Pages | published; receipt verified |
| ci | Exact-SHA private CI bridge | blocked |
| vpn | VPN implementation | deferred |
| devcontainer | Pinned credential-free public devcontainer | implemented-definition; image build unverified |
| gateway-client | Governed gateway protocol client | implemented-offline |
| gateway-logout-plan-commit | Idempotent gateway logout plan/commit | implemented-offline |
| recordings-search | Authorized local recording segment lookup | implemented-offline |

## Verification and publication

Offline regression commands:

```sh
cargo fmt --all --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
```

Cross-process safety tests use synthetic local work and real conservative intervals, never campus traffic. Initial public source [26babf3](https://github.com/cyjin-yl/buaa-cli/commit/26babf37a3e4f898af8988ad945e2af6aadfa9c4) passed independent exact-head review and offline verification before publication. [GitHub Pages documentation](https://cyjin-yl.github.io/buaa-cli/) built from that same head and was verified in Chromium. Private CI integration remains inactive; live campus/archive compatibility and a full devcontainer image build are not claimed. No credentials or personal media are needed to build or test this source.

License: [MIT](LICENSE). Reference licenses and non-adopted unsafe behaviors are recorded in the status document.
