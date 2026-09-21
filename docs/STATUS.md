# Development status

## 2026-09-20: initial offline iteration

The mounted workspace contained no project files or acceptance matrix. This iteration therefore creates original Rust source rather than claiming to resume an existing implementation. `acceptance.json` is the machine-readable scope and catalog-entry ledger. Pending means not implemented; links do not count as implemented APIs. The timed-input utility is the selected non-VPN feature. No campus request, authentication attempt, attendance action, enrolment, submission, ticket purchase or drive mutation is authorized or performed.

## Observed blockers

| Boundary | Attempted evidence | Consequence / resolution |
| --- | --- | --- |
| GitHub publication | The normal CLI profile had an unreadable preferences file. An isolated private CLI profile referencing the existing readable credential store resolved access without copying or printing credential values. Authenticated owner `cyjin-yl` and live admin/push permission were verified. | Public repository [cyjin-yl/buaa-cli](https://github.com/cyjin-yl/buaa-cli) was created after meaningful source verification and secret scanning. Initial source and Pages publication await exact-head review; no issue/PR/merge is claimed. |
| skills-fs source | The reference mount is absent; both unauthenticated and authenticated requests for the authoritative repository returned 404. | Actual Go provider, mounting and stream contract remain unavailable here. Do not invent a compatible manifest. Public napcat-cli documentation is readable but is not a substitute for the authoritative Go contract. |
| Live campus service contracts | No credentials supplied, no owner-approved read observation, no campus probes performed. | All live adapters remain pending, not declared dead or working. Build fixture-driven implementations from reviewed contracts, then request narrowly scoped read validation. No real mutations allowed by this work order. |
| Life catalog/storage | Authorized repository read access is now confirmed, but no non-sensitive storage/catalog contract has yet been reviewed. | Owner `cyjin-yl/life` is authoritative. Review only relevant contracts through authorized APIs; do not infer storage endpoints, use unrelated local research, or copy private credentials/media into public source. |
| Crater | No real allocation/API/SSH contract available in supplied context or reviewed catalog. | Await reviewed service contract and owner authorization; no guessed endpoint. |
| Gitea CI bridge | No maintainer-approved bridge contract or exact-SHA permission available. | Proposal only; no privileged workflow, unsigned claim of verification, or untrusted PR checkout with secrets. |

Rust was absent from PATH. Installed official rustup minimal toolchain privately under `/home/ezra`, not on the host. Campus rate controls were not relaxed to resolve infrastructure issues. One public GitHub raw fetch had a TLS error; no certificate-validation bypass was used.

## Reviewed sources and license boundaries

- [awesome-buaa](https://github.com/buaahub/awesome-buaa): read every catalog entry, including struck-out historical references. `acceptance.json` maps every entry to acceptance scope. The credential-stealing `buaalzm/buaaGatewayAutoLogin` entry is explicitly excluded and its repository was not fetched or executed. No catalog program was run.
- [dhy2000/TimeInput README](https://github.com/dhy2000/TimeInput): documented `[seconds]text` input, realtime pipe output and EOF semantics. Implementation here is original Rust; no source or binary copied. Upstream warns not to submit its library/source as coursework.
- [fontlos/buaa-cli](https://github.com/fontlos/buaa-cli): MIT metadata, Rust CLI, Boya/classroom/evaluation/gateway surface. Reviewed README and tree. Do not adopt password arguments, automatic check-in or TLS-disable behavior.
- [fontlos/buaa-api](https://github.com/fontlos/buaa-api): MIT metadata, undergraduate/postgraduate registration, SSO, schedules, cloud, SPOC, evaluation, gateway. Reviewed README and tree. Automatic authentication/refresh must not be adopted; deeper source/contract review remains pending.
- [BUAASubnet/UBAA](https://github.com/BUAASubnet/UBAA): MIT metadata, Kotlin multiplatform with shared/server contract separation. Reviewed README and tree; expanded Smart BUAA acceptance to cover its listed exams/rooms/library/study-room/sunlight surfaces, with owner-present restrictions. Deeper service-contract review pending.
- [BUAASubnet/srun](https://github.com/BUAASubnet/srun): GPL-3.0 metadata. README reviewed as historical/protocol context only; no code copied into this MIT project. Do not adopt rapid retries, multi-dial or TLS verification skips.
- [cyjin-yl/napcat-cli](https://github.com/cyjin-yl/napcat-cli): read the integration README and inspected `napcat_cli/data/skills-fs.json`: dynamic directories, read/write API nodes, JSON/raw write parameters and an HTTP provider URL. Its README references historical `yandu-app/skills-fs` commit `cb13f37`; that is not proof of the current `skills-fs/skills-fs` contract. A referenced fragment URL returned 404. Authoritative Go mounting/provider/stream implementation remains blocked.
- [Proto-UI AGENTS.md](https://github.com/Proto-UI/Proto-UI/blob/main/AGENTS.md) and [contributor-agent governance](https://github.com/Proto-UI/Proto-UI/blob/main/internal/agent-operations/contributor-agents.md): reviewed authority/claim/review/exact-head principles. Their repository-specific permissions do not grant permissions here.

## Next work selection

Prioritize authoritative organization directory and announcement/archive provenance after obtaining a reviewed directory source and implementing the single governed transport. Historical recordings additionally require the reviewed Life storage contract and explicit permission. Offline parsing and fixture work may continue while publication/provider access is blocked. VPN implementation alone is intentionally deferred. Never close another service acceptance item because its link was catalogued.

Directory discovery evidence: an external search returned individual department organization pages, not the university-wide authoritative directory; a refined main-domain search failed at the search providers. No campus URL was fetched and no exhaustive directory coverage is claimed.

## Verified offline iteration evidence

- `cargo test --locked --offline`: 26 passed; one ignored subprocess entry is invoked explicitly by process tests. `cargo clippy --locked --offline --all-targets -- -D warnings`: passed. Rust formatter applied.
- Actual `buaa timed-input` replay of 0.1s/0.35s offsets arrived at 0.1010s/0.3536s; raw payload/EOF matched and 24-hour dry-run returned without waiting. No network operation was involved.
- Independent CLI review: stdin OS read errors were incorrectly classified as invalid input; actual directory-stdin reproduction returned exit 2 before the fix, now regression-tested as unavailable/exit 7. Reviewer confirmed resolved.
- Independent governor review reconciled GOV-001/GOV-002/GOV-003 as resolved. Unknown outcomes no longer invent a short backoff and cannot be cleared with ordinary auth resume; the new regression failed before the fix and passed afterward. Controlled real-process first-open contention no longer strands state. Background denial is tested after the global request gap expires, with foreground admission succeeding.
- Credential-format scan across 14 explicit source/document/manifest files found no matches. This is a bounded pattern scan, not a universal guarantee; no credential/configuration values were inspected. Secret redaction boundaries also have offline regression coverage.
- That initial checkpoint marked only the local timed-input feature and shared Linux governor library implemented-offline. Later archive-adapter evidence is recorded separately below; no campus adapter, publication, PR, Pages deployment or privileged CI bridge has been completed.

Governor support boundary: all cooperating processes for one campus account must share the same effective OS UID, passwd-home state and local filesystem locking/fsync semantics. Linux boot-time deadlines include suspend. Boot-ID mismatch, unfinished request outcomes and corrupt/missing state require offline operator review; never delete governor history to regain throughput or automatically clear a lost Retry-After/latch.

## Public devcontainer definition

Added `.devcontainer/Dockerfile`, `devcontainer.json`, strict context allowlist and setup documentation. Rust 1.98.1/Node 22.23.2 official image index bytes were fetched from the registry and matched their `Docker-Content-Digest`; the pinned OMP 18.2.6 amd64 executable matched its release checksum and ran with a fresh credential-free HOME. JSON parsing, all three RUN shell syntax checks and stage-only COPY checks passed. Independent fresh-context static review reported no concrete findings.

Full image build and Dev Containers UID/volume behavior remain unverified: Docker, Podman, BuildKit, buildah and nerdctl executables and their usual local sockets are unavailable in this development seat. No host build or private operational recipe was used. The public build takes no credentials, private model configuration, GitHub hosts, SSH/service keys or Life data. Pinned runtime inputs are reproducible; image-byte reproducibility is not claimed.

## Verified archive adapter iteration

Implemented `archive lookup|capture` with cache-only default and explicit Internet Archive network opt-in. The documented CDX endpoint, exact replay URL, original Link/Memento date validation, opaque cursor handling, immutable original bytes and SHA-256, unknown publication-date confidence, scoped gaps and machine schemas are wired to real reqwest GETs—not generic success stubs or fixture-only parsers. No original campus URL is fetched.

- `cargo test --locked --offline`: **50 passed**, one intentionally ignored subprocess worker; strict all-target clippy passed and Rust formatter applied. All network test traffic was isolated loopback HTTP with synthetic data, retaining real governor intervals.
- Actual CLI `help`, `schema`, default archive lookup cache miss (exit 7), and invalid capture civil date (exit 2) were exercised without network opt-in. End-to-end loopback API proof covers rejected replay, subsequent valid refresh and offline retrieval of the retained original. Production HTTPS/live service behavior is not claimed verified by loopback tests.
- Reproduced and fixed combined HTTP Retry-After/body-failure loss: the new regression failed before the fix, then passed. HTTP status, challenge and network-body failure now persist atomically, retaining both cooldown and network backoff without manufacturing a status code.
- Independent review found ARCH-001: unvalidated replay metadata could poison an immutable cache. The new regression failed before the fix. Response normalization now runs once inside the shared lease, before cache persistence; rejected attribution never becomes an immutable original. Both protocol and safety reviewers reinspected the fix; no remaining concrete findings.
- No campus requests, authentication attempts, live Internet Archive observations or external mutations occurred. General Memento TimeGate/TimeMap crawling, college discovery, announcement extraction and Life/transcript integration remain separate pending capabilities.

Remaining proof limits: full devcontainer image build unavailable; production certificate/proxy behavior, socket teardown internals and every possible combined-signal/time-boundary case are not independently exercised by the offline suite. Namespace-isolated production CLI smoke was unavailable (`unshare` is denied), so successful capture proof uses the real API and isolated loopback transport; actual CLI checks stayed cache-only/invalid-input.

The archive checkpoint's bounded credential-format scan covered 22 explicit public source/document/manifest files with no matches; values were never printed. This is not a universal secret-detection guarantee. The project-owned working branch is `work/archive-provenance`; Git trust was scoped to individual commands for the owner-authorized workspace mount, not a global wildcard. Subsequent GitHub access recovery and repository creation are recorded above.

## Documentation landing page

`docs/index.html` is an original static, docs-first page informed by the [requested design reference](https://killaislop.com): neutral surfaces, restrained links, readable commands and explicit capability limits, without gradients or badge walls. Chromium rendered it at desktop and mobile sizes; anchor navigation worked and the mobile document had no horizontal overflow. The page loaded no external resources. Missing browser libraries were extracted privately inside this devcontainer for that proof; no private operational image recipe or host build was used. Pages deployment remains pending publication.

## Pinned Fengrubei template retrieval

Issue #9 bounds the feature to the upstream community release v1.0.3 at tag commit `20e27c67ebf09cc730d8988d7395d9a8d34acf47`. A one-time public observation used four separately governed requests (GitHub robots, fixed release URL, release-assets robots and validated asset redirect), at least five seconds after each completion. No campus endpoint, authentication, proxy, cookie, automatic redirect/retry or TLS bypass was used.

The observed release ZIP is exactly 52,816,733 bytes with SHA-256 `08b9ab2e06e440e462b6d8a65e77d579277613fe3cfb31b4bded7cd34e7177d1`. It remains in a private cache and is not committed. Archive inspection found XeLaTeX template sources, examples, prior format documents, a Windows build/cleanup script and bundled font files requiring separate license/runtime review. No upstream script, TeX or binary was executed.

`fengrubei info` is offline. `fengrubei fetch` is cache-only by default, verifies exact cache size/hash, creates a new `0600` output without overwrite and leaves the ZIP packed. Explicit `--online` performs the allowlisted governed retrieval and atomically installs the verified original. Synthetic loopback proof exercises four unchanged five-second gaps, robots, one validated redirect, streaming integrity, cache reuse, no cookies, no overwrite and corrupt-cache rejection.

`cargo fmt --all --check`, strict all-target clippy and the final offline suite passed with **54 tests** and one ignored subprocess worker. Actual CLI proof reported pinned provenance, copied the governed observed artifact from verified private cache to an owner-controlled directory with matching size/hash, denied `/tmp` (exit 5), rejected a relative `--online` path before cache/network work (exit 2), rejected an existing destination (exit 9), and made no network request during the smoke. The feature does not promise current competition-format compliance, install fonts, compile a document or convert LPPL content into project MIT source.

Independent review found five defects. Runtime input validation occurred after cache/network access and the JSON schema did not enforce absolute/non-NUL paths; both are now aligned and validated before opening the cache. Output under an attacker-writable parent could be swapped after `create_new`; output creation now pins and validates an owner-controlled, non-writable-by-others, symlink-free parent, uses descriptor-relative creation/cleanup, enforces mode `0600`, and checks the final device/inode. Cache temporary allocation after acquiring the final asset lease could strand the governor; it is now reserved before that lease, with a regression proving only the first three governed requests occur and governor state remains known on failure. A restrictive umask could cause early validation failure and leave an empty output; all post-create operations are now cleanup-guarded and `fchmod(0600)` runs before validation. Focused contract and safety re-reviews reported no remaining concrete finding.
