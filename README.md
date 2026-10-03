# buaa-cli

`buaa-cli` is an agent-facing Rust CLI. Implemented slices include offline timed-input, archive lookup/capture, policy-provenanced marks/GPA calculation, scoped credit references, pinned Fengrubei template retrieval, local recording-catalog search, official organization-directory parsing, university news-center/computer-college/integrated-circuit-college reads, and read-only SPOC public-page/source-bound script probes. Governed live observations include CDX pagination/date search and one exact 1997 homepage Memento replay with matching attribution, verified original bytes and offline reuse. Official directory, SPOC public entry and one immutable public app bundle, selected college listing/articles and one original PDF read are separately observed. This does not establish complete history, every college/faculty, historical announcement coverage or an authenticated SPOC contract. Gateway workflows remain live-unverified; no campus authentication or mutation is claimed verified. Network reads default to cache. Other acceptance items remain partial, pending or explicitly blocked; catalog links are not APIs.

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

`buaa credits calculate` implements the sourced School-8 2020 general-major calculation. `major` must match a declared non-general major tag from the catalog. Same-name catalog rows are accepted only when credit, displayed metadata and classification for that major agree; conflicting identities return `invalid_input`. Other authoritative cohort/program policies remain unverified.

`buaa credits school6` checks the pinned community description of the School-6 CS 2020 plan against operator-supplied earned courses. It reports each category deficit even when the 150-credit total is reached. Input requires `cohort: "2020"` and `courses`; each course has a stable `id`, `name`, `credits` (0.01–100 in exact hundredths), `category` from `buaa schema`, and explicit `passed`. Optional `qualifications` attest eligible local `english`, non-practical `english_exchange`, `cross_major` and `humanities_core` attributes. Local English witnesses use core-major/general-major/general-education categories; exchange English witnesses may use any primary category. Both require one 2-credit course and never add witness credits again. A course ID identifies the same course across attempts, not an individual attempt: any listed pass counts once; conflicting name, credit, category or attributes are rejected.

```sh
# Synthetic earned-course declaration; reports deficits, not campus records.
printf '%s\n' '{"cohort":"2020","courses":[{"id":"example","name":"Synthetic elective","credits":2,"category":"general_major","passed":true,"qualifications":{"english":true}}]}' | ./target/debug/buaa credits school6
```

Source: [pinned community explanation](https://github.com/TrickEye/can_I_Graduate/blob/5e0f0355455d7eb7e69f953a23ca405e5af7ebed/src/App.vue#L450-L461). Numerical requirement facts inform original code; the unlicensed upstream implementation is neither copied nor executed. Classification, passing status and eligible course attributes remain operator assertions. The result always has `graduation_eligibility: "not_verified"`; official retake, substitution, waiver, overlap rules and full catalog validation remain missing. Both commands are fully offline and do not fetch grades or certify graduation.

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

The integrated-circuit college is bound to its exact non-hidden HTTPS member in the retained authoritative directory. `announcements college-source ic [root|notices]` observes fixed public pages; its root must actually declare the notice board. Supply `{"college":"ic","page":2}` to `announcements list` (`tzgg` only); its observed page2 is `/tzgg/22.htm`, never a guessed page address. IC `article` URLs under `/info/1042/` must be linked by the retained notice listing. Optional `source_page` selects that source-advertised listing ordinal; only IC, aviation, Beijing and Shenyuan articles accept a non-null value. Directory/root/list discovery stays cache-first, while only the explicitly selected target refreshes on the same source/cache/governor. Foreign/query/credential routes, undeclared articles, untyped or base-changed source HTML fail closed.

```sh
# Cache-only selected source and bound non-personal policy; no network.
printf '%s\n' '{"college":"ic","since":"2026-09-01","match":"评审方案"}' | ./target/debug/buaa announcements list
printf '%s\n' '{"url":"https://ic.buaa.edu.cn/info/1042/4815.htm"}' | ./target/debug/buaa announcements article
```

IC observations cover two notice pages and one policy article, not full history or all colleges. Shared IC/aviation directory admission requires the exact literal and resolved root of one non-hidden member; a normalized alias alone cannot authorize the source. The title comes from the article's `ar_tit/h3`, not its sidebar `h2`; the publication header and 38 source paragraphs were verified against retained original bytes after a real sidebar-title regression was fixed. Body extraction requires one source `v_news_content` container; ambiguous containers fail closed instead of combining prose or guessing an IC desktop/mobile selector. A typed HTML layout drift remains an unavailable error, while the private original can be reparsed offline without another request. Source bytes are not published and attachment hints are not downloads. [Bounded source evidence and limits](docs/STATUS.md#2026-10-03-directory-bound-integrated-circuit-college-notices).

The aviation college binds the directory's non-hidden 飞行学院 member and its literal HTTPS URL. `announcements college-source aviation [root|notices|public-notices]` observes only fixed, root-declared pages. `{"college":"aviation"}` selects student notices (`tzgg`); `{"college":"aviation","category":"gkgs"}` selects 公开公示. Listing dates use the actual year/day/slash-month markup, and mobile copies are not extra rows. The observed student board has four external WeChat links, retained but never followed; the public board has one own-site article. Aviation `/info/1061/` articles must be declared by that retained public board; `source_page` defaults to 1 and must be source-advertised when selecting a later ordinal. Actual cached article output has the source title, 2026-09-22 publication date and 15 desktop paragraphs, not 30 responsive copies. Original HTML and any personal prose stay private; public proof uses only retrieval/structural facts and synthetic fixtures. No external-body, complete-history, all-college or faculty-coverage claim. [Aviation evidence and limits](docs/STATUS.md#2026-10-03-directory-bound-aviation-college-notices).

```sh
# Cache-only source and dated student-notice listing; no network request.
./target/debug/buaa announcements college-source aviation notices
printf '%s\n' '{"college":"aviation","category":"tzgg","since":"2025-04-03","until":"2025-04-03"}' | ./target/debug/buaa announcements list
```

The Beijing college binds the official directory's non-hidden 北京学院 member and exact literal/resolved HTTPS root. `announcements college-source beijing [root|notices]` reports fixed source metadata; the retained root must declare `/xwdt/gggs.htm`. `{"college":"beijing"}` selects that board (`gggs` only); its three observed dates are 2026-09-22, 2026-09-22 and 2026-09-08. Listing dates come from `a/span` in `YYYY.MM.DD`, not summaries. Selected canonical `/info/1014/` articles must be declared by the retained listing, with optional `source_page` bound to an advertised ordinal. The actual original has one `art-main`, its direct `art-tit/h3` heading, a Chinese publication date in the direct header, and one `vsb_content/v_news_content` body. Offline extraction preserves all 795 nonempty paragraphs, including table-cell paragraphs; it does not promote sidebar headings or body dates. Source discovery stays cache-first and only a selected target may refresh on the existing governor. Original HTML, table contents and personal prose stay private. One current board/article is not all-college or historical coverage. [Beijing source evidence](docs/STATUS.md#2026-10-03-directory-bound-beijing-college-notices).

```sh
# Cache-only Beijing source and dated listing; no network request or raw article output.
./target/debug/buaa announcements college-source beijing notices
printf '%s\n' '{"college":"beijing","since":"2026-09-22","until":"2026-09-22"}' | ./target/debug/buaa announcements list
```

The Shenyuan college binds non-hidden 沈元学院 member39 and exact literal/resolved `https://hc.buaa.edu.cn/`; the hidden shared-host member40 is not an alias. `announcements college-source shenyuan [root|notices]` observes the root-declared `/index/tzgg.htm`; `{"college":"shenyuan"}` selects its canonical `tab_a1/list_box_03s` rows (`tzgg` only), not duplicated alternate views. The observed page has 12 rows, including three preserved, unfetched dynamic JSP links. Dates come from separate `DD` and `YYYY-MM` fields. Canonical declared `/info/1083/` articles use their own direct `nav01/h3` heading, first header-date span and unique `vsb_content_2/v_news_content` body. The selected original returns 2026-09-29 and all seven ordered paragraphs; its heading differs from the listing teaser and is not silently replaced. Missing header dates stay null, ambiguity remains an error, and dynamic URLs are not converted to guessed permalinks. This owned source is explicitly stacked on unmerged PR96/PR94, not root-main or deployed coverage. [Shenyuan evidence and limits](docs/STATUS.md#2026-10-03-directory-bound-shenyuan-college-notices).

```sh
# Cache-only Shenyuan source and inclusive date selection; no raw article output.
./target/debug/buaa announcements college-source shenyuan notices
printf '%s\n' '{"college":"shenyuan","since":"2026-09-18","until":"2026-09-29"}' | ./target/debug/buaa announcements list
```

Shared text reads retain at most 1,024 nonempty source paragraphs, each at most 8 KiB, from HTML bounded to 2 MiB. Overflow is an error rather than truncation; no URL/source-specific allowance exists. The previous 512-paragraph limit rejected a legitimate 795-paragraph table notice; a synthetic 1,024/1,025 boundary reproduced red before the shared limit correction and passes green. This does not relax request, authentication or account-safety limits.

Some computer-college policies are image/PDF-preview pages. They return `embedded_document` or `partial_text`, not invented plaintext: preview scripts are excluded, OCR is not performed, and attachment/preview paths are unverified hints, never downloads. Historical SCSE listing bytes stay offline and operator-asserted, including original HTTP source URLs. Colleges beyond the individually observed slices and complete historical coverage remain unimplemented.

`announcements document [--online|--refresh]` accepts `{"article_url":"https://scse.buaa.edu.cn/info/1099/12508.htm"}` on stdin. It retrieves only the original PDF explicitly declared by that reviewed article's viewer, never an inferred original from image names or an arbitrary URL. Output preserves the original bytes as base64, byte length and SHA-256, with separate article-snapshot/document retrieval facts. Source scripts are not executed; other attachments and previews are not fetched. The private byte cache is immutable for the document URL.

`document --refresh` revalidates the PDF against its retained source-article snapshot; use `article --refresh` separately to update that declaration. A cold source/robots cache may require another deliberate invocation after spacing, never an automatic retry. PDF MIME/header/EOF framing is checked, not publisher signatures, externally published checksums or document safety. CLI text extraction/OCR is not performed; any operator-extracted text is a derivative of the linked original bytes, not reconstructed webpage text.

The retired `www.buaa.edu.cn/xwzx.htm` source returned HTTP 404. `buaa announcements list` now reads `news.buaa.edu.cn`: default `tzgg` (通知公告), with `zhxw` (综合新闻) and the other section slugs exposed in `buaa schema`. Optional stdin JSON accepts `category`, `page`, inclusive `since`/`until` dates and a title-substring `match`. Missing dates stay null and cannot satisfy a date filter. Later page ordinals must be advertised by the latest listing: the site's page 2 can be `tzgg/252.htm`, not `tzgg/2.htm`. No address is guessed and no pages are automatically traversed.

```sh
# Cache only; these commands do not fetch campus pages.
printf '%s\n' '{"since":"2026-09-01","match":"交换"}' | ./target/debug/buaa announcements list
printf '%s\n' '{"url":"https://news.buaa.edu.cn/info/1010/69802.htm"}' | ./target/debug/buaa announcements article
```

`article` returns the selected page's `v_news_content` paragraphs, publication date and attachment-link hints; it never downloads attachments. Use `--online` for an authorized cache miss or `--refresh` for conditional revalidation. Robots and content requests each retain the same cross-process governor lease. With the operator's raised 60-second interval, a cold robots fetch can leave the content request beyond the 30-second bounded wait; the CLI reports rate-limited and never retries automatically.

`announcements history` remains fully offline for the news-center and reviewed SCSE listing sources: base64 UTF-8 HTML with asserted `provenance.source_url`, optional `capture_timestamp` and `asserted_by`. Output is `announcements_history`, with `retrieval.sha256` binding the supplied bytes. Provenance is operator-asserted, not verified archive attribution. IC/aviation/Beijing/Shenyuan archive extraction, further college-site adapters, broader faculty/college coverage, complete history and broader attachment retrieval remain unimplemented. [Current proof and limitations](docs/STATUS.md#2026-09-29-announcements-news-center-migration).

## SPOC public sources (contract evidence)
`buaa spoc surface [root|entry]` observes fixed public pages. `buaa spoc script` accepts a JSON URL on stdin only if the retained entry actively declares that same-host, query-free `/spocnew/js/<name>.<8hex>.js` source. Both use the same private cache/account-wide governor and report sanitized metadata, not raw HTML/JavaScript, fields, values or source configuration. No script execution, authentication or course/media operation.

```sh
# Private cache only; no network request.
./target/debug/buaa spoc surface
printf '%s' '{"url":"https://spoc.buaa.edu.cn/spocnew/js/app.a7c0879c.js"}' |
  ./target/debug/buaa spoc script
```

Use `--online` only for an authorized cache miss. `surface entry --refresh` updates declarations in one selected request; `script --refresh` revalidates only the selected immutable script, keeping entry discovery cache-first. The filename fingerprint is not a checksum. [docs/SPOC.md](docs/SPOC.md) records the changed entry declaration, prior refused old-script request, actual 2,424,757-byte public app/hash/offline proof and safety limits. The SPOC item stays **blocked** until the authenticated contract, private credential delivery and rights-cleared course inventory exist.

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

Unknown request outcomes (including crash or failed outcome persistence), reboot/boot-ID mismatch and corrupt/missing governor history fail closed. Ordinary auth resume does **not** clear these states. A known pre-reboot history can be deliberately migrated with the local-only `governor boot-review-plan` and `governor boot-review-commit --offline` flow below; missing/corrupt history and unfinished outcomes remain blocked, with no reset or automatic recovery. Gateway logout unknown outcomes have a separate typed, local-only review flow that records `remote_state=unknown` and cannot clear governor state. Local filesystem locking/fsync semantics and cooperating same-UID clients are required.

### Deliberate offline boot-history review

Run `buaa governor boot-review-plan` to inspect a credential-free preview. It creates no history, sends no request, and binds the exact old state bytes and current Linux boot identity. Independently inspect the retained history and preview before supplying the unchanged plan on stdin to `buaa governor boot-review-commit --offline`, with `intent` exactly `MIGRATE GOVERNOR BOOT <plan_hash>`. The commit object has only `plan` and `intent`; `buaa schema` exposes both input and output contracts. There is no `--online` variant, path override, unattended resume loop, or authentication grant.

Commit rechecks the whole preview under the existing permanent account lock. Before replacing current state, it durably preserves the complete original bytes in a new private `boot-review-<plan_hash>.json` snapshot without overwrite. It reserves the **entire** recorded remaining request/background/cooldown delays from the current boot, taking no elapsed-time credit from UTC, uptime, file timestamps or time since reboot. Raised request/background limits are retained and impose fresh full policy gaps; saturated deadlines stay saturated, rejection latches and failure history stay intact, and old authentication permission is disarmed. Stale/tampered previews, unfinished outcomes and incomplete/unsafe retained snapshots fail closed. Repeating a completed migration conflicts without changing the new state.

This is an explicit local state transition, not campus access permission or a remote postcondition check. A persistence error requires inspection of retained/current history before further action; never delete or rename governor history, change account keys, or lower pacing to bypass the failure.

See [contributor rules](AGENTS.md), [observed blockers and source research](docs/STATUS.md), and `acceptance.json` for the full 74-entry catalog mapping, including historical entries and the excluded credential-stealing entry. Catalog links are not API implementations. School-specific credit policies and historical systems require explicit evidence, never guessed behavior.

## Feature acceptance matrix

This table projects `acceptance.json`; update both together. `implemented-offline` verifies a local feature/library; `implemented-offline-tested` verifies an adapter against offline HTTP fixtures; `implemented-observed-read` additionally records a bounded authorized source observation. `partial-offline` has a working offline slice; `partial-live-verified` has bounded observed reads with named remaining gaps; `partial-live-unverified` lacks authorized live proof. None implies complete parent acceptance. `pending` means not implemented, `blocked` names a prerequisite, and `deferred` applies only to VPN.

| ID | Capability | Status |
| --- | --- | --- |
| governor | Shared cross-process request safety | implemented-offline |
| gateway | Gateway login/logout/usage | partial-live-unverified |
| spoc | SPOC materials/video/PPT/subtitles | blocked |
| live | Classroom live replay/audio repair | blocked — verified current endpoint/session/read contract, accessible authorized inventory, private credentials and original/derivation provenance remain missing ([owner-closed historical issue #47](https://github.com/cyjin-yl/buaa-cli/issues/47)) |
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
| announcements | College current/historical announcements | partial-live-verified: bounded university/computer/IC/aviation/Beijing/Shenyuan sources and one original PDF; broader sources/history pending |
| archive | CDX/Memento historical lookup | partial-live-verified: dated index and one exact homepage replay; broader history pending |
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
