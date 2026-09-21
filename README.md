# buaa-cli

Rust CLI for agent-facing BUAA tools. Timed-input replay and historical archive lookup/capture are implemented and tested offline. Archive reads default to local cache; explicit opt-in can contact Internet Archive only. No campus adapter or authentication command is enabled, and live archive compatibility has not been observed. The acceptance ledger below distinguishes implemented work from pending or blocked services.

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

Errors are JSON on stderr with `schema_version`, `error` and sanitized `message`. Exit codes: 2 invalid input, 3 unsupported, 4 safety/auth-latched, 5 permission, 7 unavailable I/O, 8 rate-limited and 9 immutable-content conflict. There is no login/unlock command. A replay I/O failure may leave earlier events delivered; do not blindly restart a pipe into a side-effectful program.

## Historical archive reads

`buaa archive lookup` accepts an exact original URL, optional inclusive UTC date bounds and a continuation cursor. `buaa archive capture` retrieves an exact timestamped replay with matching Memento attribution, original-byte SHA-256 and base64 bytes. Publication dates stay unknown; capture time is not publication time, and gaps are never reconstructed.

```sh
# Synthetic example: default cache-only lookup, no network request.
printf '%s\n' '{"url":"https://college.example/notice/42.html","limit":100}' | ./target/debug/buaa archive lookup
```

Use `--online` only for authorized archive reads on cache misses, or `--refresh` for conditional revalidation. Robots rules, the shared governor, fixed HTTPS routes and immutable-original conflict checks apply. Rejected provenance never becomes an immutable cache entry. See [archive contracts and examples](docs/ARCHIVE.md); live service availability remains unverified.

## Pinned Fengrubei template access

`buaa fengrubei info` reports an immutable upstream release reference, LPPL license, byte/hash integrity and caveats without network access. `fengrubei fetch` copies only the verified original ZIP from a private cache to an explicit new absolute path.

```sh
./target/debug/buaa fengrubei info
printf '%s\n' '{"output":"/home/operator/private/template-v1.0.3.zip"}' | ./target/debug/buaa fengrubei fetch
```

Use `fetch --online` only to permit a governed public download on cache miss. The output parent must already exist, be owned by the current user, reject group/other writes, and contain no symlink path components. The client checks robots on both GitHub hosts, validates one explicit redirect, streams and verifies 52,816,733 bytes, and never unpacks, executes, compiles or overwrites. See [license, font and format caveats](docs/FENGRUBEI.md). The community release is not an official/current-format guarantee.

## Account safety

Archive and template network reads share the process-wide governor for request, bounded response processing and private atomic persistence. The archive adapter fetches no original campus URL; the template adapter permits only one pinned GitHub release and validated release-asset redirect. All future adapters/provider processes must share the same state domain and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, autonomous auth retry, CAPTCHA bypass or real development-time campus mutation is allowed.

The Linux governor uses `.buaa-cli-governor` beneath the effective UID's passwd home, ignoring HOME/XDG/worktree overrides. One permanent file lock spans the full request/body lifetime; private atomic state preserves minimum 5-second completion gaps, 15-minute background intervals, Retry-After and one-shot auth permission. Boot-time deadlines cannot be shortened by wall-clock changes. All processes using a campus account must share this OS identity and filesystem state; this is not a distributed cross-host governor.

Unknown request outcomes (including crash or failed outcome persistence), reboot/boot-ID mismatch and corrupt/missing history fail closed. Ordinary auth resume does **not** clear unknown outcomes or cooldowns. These conditions require offline operator review; no automatic reset/recovery command is provided. Local filesystem locking/fsync semantics and cooperating same-UID clients are required.

See [contributor rules](AGENTS.md), [observed blockers and source research](docs/STATUS.md), and `acceptance.json` for the full 74-entry catalog mapping, including historical entries and the excluded credential-stealing entry. Catalog links are not API implementations. School-specific credit policies and historical systems require explicit evidence, never guessed behavior.

## Feature acceptance matrix

This table projects `acceptance.json`; update both together. `implemented-offline` verifies a local feature/library; `implemented-offline-tested` verifies an adapter against offline HTTP fixtures, and `implemented-observed-read` additionally records a bounded public source observation. `pending` means not implemented, `blocked` names a missing prerequisite, and `deferred` applies only to VPN.

| ID | Capability | Status |
| --- | --- | --- |
| governor | Shared cross-process request safety | implemented-offline |
| gateway | Gateway login/logout/usage | pending |
| spoc | SPOC materials/video/PPT/subtitles | pending |
| live | Classroom live replay/audio repair | pending |
| smart | Smart BUAA services | pending |
| enrol | Undergraduate/postgraduate course selection/drop | pending |
| evaluation | Teaching evaluations | pending |
| marks | Marks/GPA/change monitoring | pending |
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
| credits | School-specific graduation credits | pending |
| shuttle | Shuttle tickets | pending |
| welearn | WE Learn materials/practice | pending |
| fengrubei | Fengrubei template access | implemented-observed-read |
| crater | Crater allocation/API/SSH | blocked |
| organizations | Authoritative college/institute directory | pending |
| announcements | College current/historical announcements | pending |
| archive | CDX/Memento historical lookup | implemented-offline-tested; live unverified |
| recordings | Historical recordings/transcript segments | pending |
| life | Life external object storage/catalog | pending contract review |
| skills-fs | skills-fs HTTP provider | blocked |
| contribution | Governed autonomous contribution | pending |
| drift | Read-only API/schema drift detection | pending |
| publication | GitHub repository and Pages | repository created; publication in progress |
| ci | Exact-SHA private CI bridge | blocked |
| vpn | VPN implementation | deferred |
| devcontainer | Pinned credential-free public devcontainer | implemented-definition; image build unverified |

## Verification and publication

Offline regression commands:

```sh
cargo fmt --all --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
```

Cross-process safety tests use synthetic local work and real conservative intervals, never campus traffic. The public [cyjin-yl/buaa-cli repository](https://github.com/cyjin-yl/buaa-cli) has been created with verified owner permissions; initial source and Pages publication are in progress. Private CI integration remains inactive. No credentials or personal media are needed to build or test this source.

License: [MIT](LICENSE). Reference licenses and non-adopted unsafe behaviors are recorded in the status document.
