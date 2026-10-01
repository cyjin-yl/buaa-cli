# buaa-cli

`buaa-cli` is an agent-facing Rust CLI. Implemented slices include offline timed-input, archive lookup/capture, policy-provenanced marks/GPA calculation, scoped credit calculation, pinned Fengrubei template retrieval, local recording-catalog search, official organization-directory parsing, university-wide news-center reads, and a read-only SPOC public-surface contract probe. Governed live Internet Archive CDX, official directory, SPOC public-surface, and news-center listing/article reads were manually observed; this does not establish complete history, live Memento replay, per-college coverage, or an authenticated SPOC contract. Gateway workflows remain live-unverified; no campus authentication or mutation is claimed verified. Network reads default to cache. Other acceptance items remain partial, pending or explicitly blocked; catalog links are not APIs.

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

Errors are JSON on stderr with `schema_version`, `error` and sanitized `message`. Exit codes: 2 invalid input, 3 unsupported, 4 safety/auth-latched, 5 permission, 7 unavailable I/O, 8 rate-limited and 9 conflict or unknown outcome. Gateway authentication requires an explicit typed `resume-auth` before exactly one online login flow; there is no automatic refresh/retry. A replay I/O failure may leave earlier events delivered; do not blindly restart a pipe into a side-effectful program.

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
The example values are placeholders. Login uses an explicit resume and typed intent. Every offline `logout-plan` creates a fresh operation ID; `logout-commit --online` binds that ID to the typed commit and reuses only its own successful receipt. Indeterminate outcomes leave an account-wide barrier that requires the typed, local-only `logout-recovery-plan` and `logout-recovery-commit --offline` flow; recovery reports `remote_state=unknown` and never retries or claims disconnection. The CLI performs no HTTP AC discovery, interface/DNS probe, credential storage, password argument, automatic retry, invalid-certificate mode or challenge/security-notice bypass. See [gateway safety, usage and mutation contracts](docs/GATEWAY.md).
Archive and gateway requests share the process-wide governor through request, bounded response classification and private persistence. The archive adapter fetches no original campus URL; gateway egress is fixed to TLS-validated `gw.buaa.edu.cn` paths. All future adapters/provider processes must share the same state domain and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, automatic authentication retry, CAPTCHA bypass or development-time campus mutation is allowed.
## Authoritative organization directory
`buaa organizations list` returns every entry in the captured official BUAA `教学科研机构` document, including hidden source entries and explicit missing/non-HTTP links. It never invents a URL or silently upgrades HTTP links.
# Private cache only; no network request.
./target/debug/buaa organizations list
Use `--online` only for an authorized cache miss, or `--refresh` for conditional revalidation. Egress is limited to the official robots and directory URLs and shares the same process-wide governor. See [directory semantics and governed observation evidence](docs/ORGANIZATIONS.md) and the [sanitized 2026-09-20 snapshot](docs/data/organizations-2026-09-20.json). Announcement crawling remains separate.
`src/net.rs` implements allowlisted archive and official-directory GETs through `src/governor.rs`; the organization command fetches no linked college site, and the archive command fetches no original campus URL. All future adapters/provider processes must retain the same request lease through response validation and persistence, share one private state domain, and use cache-first conditional reads. No per-worktree limiter, parallel account alias, fast-test production mode, autonomous auth retry, CAPTCHA bypass or real development-time campus mutation is allowed.
## University-wide announcements and news

The computer-college notice board has a separate observed CMS contract. Supply `{"college":"scse","since":"2026-09-01"}` to `announcements list`; its category is `gggs` and later pages follow only source-advertised ordinals. Article URLs on `scse.buaa.edu.cn` in reviewed notice categories 1099/1299 use the college-specific title/date parser. `announcements college-source scse [root|notices]` reports source evidence without following hints. All commands default to the existing private cache and reuse the same process-shared governor.

Some college policies are image/PDF-preview pages. They return `embedded_document` or `partial_text`, not invented plaintext: preview scripts are excluded, OCR is not performed, and attachment/preview paths are unverified hints, never downloads. Historical SCSE listing bytes stay offline and operator-asserted, including original HTTP source URLs. Other colleges and complete historical coverage remain unimplemented.

`announcements document [--online|--refresh]` accepts `{"article_url":"https://scse.buaa.edu.cn/info/1099/12508.htm"}` on stdin. It retrieves only the original PDF explicitly declared by that reviewed article's viewer, never an inferred original from image names or an arbitrary URL. Output preserves the original bytes as base64, byte length and SHA-256, with separate article-snapshot/document retrieval facts. Source scripts are not executed; other attachments and previews are not fetched. The private byte cache is immutable for the document URL.

`document --refresh` revalidates the PDF against its retained source-article snapshot; use `article --refresh` separately to update that declaration. A cold source/robots cache may require another deliberate invocation after spacing, never an automatic retry. PDF MIME/header/EOF framing is checked, not publisher signatures, externally published checksums or document safety. CLI text extraction/OCR is not performed; any operator-extracted text is a derivative of the linked original bytes, not reconstructed webpage text.

The retired `www.buaa.edu.cn/xwzx.htm` source returned HTTP 404. `buaa announcements list` now reads `news.buaa.edu.cn`: default `tzgg` (通知公告), with `zhxw` (综合新闻) and the other section slugs exposed in `buaa schema`. Optional stdin JSON accepts `category`, `page`, inclusive `since`/`until` dates and a title-substring `match`. Missing dates stay null and cannot satisfy a date filter. Later page ordinals must be advertised by the latest listing: the site's page 2 can be `tzgg/252.htm`, not `tzgg/2.htm`. No address is guessed and no pages are automatically traversed.

```sh
# Cache only; these commands do not fetch campus pages.
printf '%s\n' '{"since":"2026-09-01","match":"交换"}' | ./target/debug/buaa announcements list
printf '%s\n' '{"url":"https://news.buaa.edu.cn/info/1010/69802.htm"}' | ./target/debug/buaa announcements article
```

`article` returns the selected page's `v_news_content` paragraphs, publication date and attachment-link hints; it never downloads attachments. Use `--online` for an authorized cache miss or `--refresh` for conditional revalidation. Robots and content requests each retain the same cross-process governor lease. With the operator's raised 60-second interval, a cold robots fetch can leave the content request beyond the 30-second bounded wait; the CLI reports rate-limited and never retries automatically.

`announcements history` remains fully offline: base64 UTF-8 HTML with `provenance.source_url` identifying a news-center listing, optional `capture_timestamp` and `asserted_by`. Output is `announcements_history`, with `retrieval.sha256` binding the supplied bytes. Provenance is operator-asserted, not verified archive attribution. Other college-site adapters, broader faculty/college coverage, complete history and attachment retrieval remain unimplemented. [Current proof and limitations](docs/STATUS.md#2026-09-29-announcements-news-center-migration).

## SPOC public surface (contract evidence)
`buaa spoc surface` is read-only contract tooling for the SPOC acceptance item, not an authenticated adapter. It fetches the two fixed public SPOC pages through the same process-wide governor (robots policy first) and reports only sanitized structural facts: status, content type, byte length, SHA-256, document title and form shape. Bodies, field names and values never enter output, logs or the repository; no authentication is attempted.
# Private cache only; no network request.
./target/debug/buaa spoc surface
Use `--online` only for an authorized cache miss, or `--refresh` for conditional revalidation. Egress is limited to `spoc.buaa.edu.cn` robots, `/` and `/spocnew/`. A 2026-09-28 governed observation is recorded in [docs/SPOC.md](docs/SPOC.md) as a **pending-review** contract draft; the SPOC item stays blocked until the owner reviews the contract and supplies a rights-cleared course inventory.

## Contract drift detection (offline)
`buaa drift check` compares a pinned baseline contract document against a candidate contract document, both supplied as JSON on stdin. It is fully offline: no network access, no writes. The output is a JSON drift report naming added, removed, type-changed and array-length-changed paths (with type names and lengths) and never applies, guesses or merges a change. Raw document values never enter the report.

```sh
printf '%s\n' '{"baseline":{"v":"s"},"candidate":{"v":5}}' | ./target/debug/buaa drift check
```


## Timetable to ICS (offline)
`buaa timetable ics` turns operator-supplied JSON on stdin into a standards-compliant RFC 5545 ICS calendar. It is fully offline: no network access, no writes, no campus contact. `semester.start_date` is the week-1 Monday; each occurrence lands on `start_date + (week - 1) * 7 + day_offset`, so dates are computed from the anchor rather than asserted. `parity` (`all`/`odd`/`even`) filters weeks, and occurrences that fall past the semester end are dropped. Output uses CRLF line endings, 75-octet folding on UTF-8 character boundaries, and RFC 5545 text escaping.

```sh
printf '%s\n' '{"semester":{"start_date":"2026-09-21","weeks":16},"courses":[{"name":"Mathematics","day":"monday","start_week":1,"end_week":16,"start_time":"08:00","end_time":"09:40"}]}' | ./target/debug/buaa timetable ics
```


## Physics experiment data processing (offline)
`buaa physics <method>` performs documented, unit-explicit experiment data reduction in SI. It is fully offline: no network access, no campus contact, no writes. Methods read JSON on stdin and emit a typed JSON result with explicit units.

- `physics type-a` — repeated measurements: sample mean, (n-1) sample standard deviation and standard uncertainty of the mean `s/sqrt(n)`.
- `physics fit` — ordinary least-squares line `y = intercept + slope*x` with parameter standard errors and r-squared.
- `physics pendulum` — gravity from `g = 4*pi^2*L/T^2` with `T = total_time_s/cycles`, combined standard uncertainty from the sensitivity coefficients `dg/dL = g/L` and `dg/dT = -2g/T`.

```sh
printf '%s\n' '{"length_m":0.980,"length_uncertainty_m":0.001,"cycles":50,"total_time_s":99.50,"total_time_uncertainty_s":0.05}' | ./target/debug/buaa physics pendulum
printf '%s\n' '{"points":[[0,0.2],[1,0.9],[2,2.1],[3,3.0],[4,4.2],[5,4.9]]}' | ./target/debug/buaa physics fit
printf '%s\n' '{"samples":[0.980,0.978,0.981,0.979,0.980]}' | ./target/debug/buaa physics type-a
```

The Linux governor uses `.buaa-cli-governor` beneath the effective UID's passwd home, ignoring HOME/XDG/worktree overrides. One permanent file lock spans the full request/body lifetime; private atomic state preserves minimum 5-second completion gaps, 15-minute background intervals, Retry-After and one-shot auth permission. Boot-time deadlines cannot be shortened by wall-clock changes. All processes using a campus account must share this OS identity and filesystem state; this is not a distributed cross-host governor.

Unknown request outcomes (including crash or failed outcome persistence), reboot/boot-ID mismatch and corrupt/missing governor history fail closed. Ordinary auth resume does **not** clear these states; governor-state failures still require offline operator review and have no reset command. Gateway logout unknown outcomes have a separate typed, local-only review flow that records `remote_state=unknown` and cannot clear governor state. Local filesystem locking/fsync semantics and cooperating same-UID clients are required.

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
| timetable-ug | Undergraduate timetable/ICS | implemented-offline |
| timetable-pg | Postgraduate timetable/ICS | pending |
| checkin | Classroom QR/direct check-in | pending |
| boya | Boya browse/enrol/drop/check/status | pending |
| ihome | ihome announcements | pending |
| electricity | Electricity query/alerts | pending |
| physics-select | Physics experiment selection | pending |
| physics-data | Physics experiment data processing | implemented-offline |
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
| announcements | College current/historical announcements | partial-live-verified: university-wide listings/articles; college adapters pending |
| archive | CDX/Memento historical lookup | implemented-offline-tested |
| recordings | Historical recordings/transcript segments | partial: local catalog search; remote media pending |
| life | Life external object storage/catalog | partial: read-only catalog profile; object retrieval pending |
| skills-fs | skills-fs HTTP provider | blocked |
| contribution | Governed autonomous contribution | pending |
| drift | Read-only API/schema drift detection | implemented-offline |
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
