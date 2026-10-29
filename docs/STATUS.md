## Development status

## Classroom CAS callback: evidence boundary

`sso.buaa.edu.cn` is the sign-on service in the observed classroom flow;
`yjapi.msa.buaa.edu.cn/casapi/index.php` is the classroom relying-party
callback. Sanitized CLI receipts recorded a credential POST redirect followed
by callback HTTP 500, without a positively verified selected-lesson session.
The callback error cause, the deployed ticket lifetime and a password verdict
remain unknown; an HTTP status or redirect alone does not establish them.

On 2026-10-29, one newly authorized attempt ran under the shared heavy-work
guardian and the existing v2 account governor. An explicit resume armed one
attempt; the CLI then observed SSO HTTP 200, a credential POST redirect, and
classroom callback HTTP 500. The login returned `auth_latched`, stored no
session and did not positively confirm the selected lesson. After completion
the account governor was latched, authentication was disarmed and no outcome
was pending. The one-shot authorization was consumed; no automatic retry or
challenge bypass was performed. These facts do not identify the HTTP 500 cause
or establish a password verdict, media access or playback rights.

Earlier ad hoc clients returned both redirects and HTTP 500 at different delays,
but their distinct credential submissions and cookie handling were not a
controlled same-request comparison. Those scripts did not use the production
shared governor, and their outcomes are not admitted as online acceptance or
proof of a ticket-expiration threshold, cookie necessity, playback permission
or a server defect. The attempted shorter redirect interval and broader SSO
cookie delivery were withdrawn; the existing configured governor floor,
cooldowns and sign-on cookie isolation remain in force.

[Issue #132](https://github.com/cyjin-yl/buaa-cli/issues/132) was corrected
on 2026-10-28 to withdraw its unsupported claims about all tickets and a PHP
defect. The issue remains open for an independently supported investigation.

An ungoverned exploratory course-list response and source-code references to
live URLs do not prove access rights, successful media delivery or real player
output. The live goal remains open until an authorized source, a governed media
path and actual player and subtitle observations are bound together.

Open GitHub acceptance trackers now cover source-bound replay and subtitle
synchronization ([#133](https://github.com/cyjin-yl/buaa-cli/issues/133)), iHome
([#134](https://github.com/cyjin-yl/buaa-cli/issues/134)), aerospace study
([#135](https://github.com/cyjin-yl/buaa-cli/issues/135)), department materials
([#136](https://github.com/cyjin-yl/buaa-cli/issues/136)), drive reads
([#137](https://github.com/cyjin-yl/buaa-cli/issues/137)), live playback
([#138](https://github.com/cyjin-yl/buaa-cli/issues/138)), gateway login
([#139](https://github.com/cyjin-yl/buaa-cli/issues/139)) and WE Learn
([#140](https://github.com/cyjin-yl/buaa-cli/issues/140)). Further trackers
cover shuttle ([#141](https://github.com/cyjin-yl/buaa-cli/issues/141)), smart
services ([#142](https://github.com/cyjin-yl/buaa-cli/issues/142)), OS lab
([#143](https://github.com/cyjin-yl/buaa-cli/issues/143)), physics selection
and references ([#144](https://github.com/cyjin-yl/buaa-cli/issues/144),
[#145](https://github.com/cyjin-yl/buaa-cli/issues/145)), postgraduate timetable
([#146](https://github.com/cyjin-yl/buaa-cli/issues/146)), enrolment
([#147](https://github.com/cyjin-yl/buaa-cli/issues/147)), contribution
([#148](https://github.com/cyjin-yl/buaa-cli/issues/148)), evaluation
([#149](https://github.com/cyjin-yl/buaa-cli/issues/149)), Boya
([#150](https://github.com/cyjin-yl/buaa-cli/issues/150)), electricity
([#151](https://github.com/cyjin-yl/buaa-cli/issues/151)), check-in
([#152](https://github.com/cyjin-yl/buaa-cli/issues/152)) and CourseGrading
([#153](https://github.com/cyjin-yl/buaa-cli/issues/153)). These issues record
remaining work and prerequisites; they are not PRs or evidence of acceptance.

The documentation correction is published as draft
[#154](https://github.com/cyjin-yl/buaa-cli/pull/154), exact head
`c34353fc5882d539dee6c42ddaf510bfa8357960`, above PR #131 in native
[stack #155](https://github.com/cyjin-yl/buaa-cli/stack/155). The local replay
receipt-binding layer is draft [#156](https://github.com/cyjin-yl/buaa-cli/pull/156),
exact head `d3e9ca17cd2852f3441ace022268eaa7b5f49091`, directly above #154.
Its five offline CLI cases and a separate inotify smoke passed; the container
has no mpv or VLC, so this does not establish playback or media rights. Scoped
independent source reviews found no remaining concrete issues in these two
layers. Offline subtitle export is draft
[#157](https://github.com/cyjin-yl/buaa-cli/pull/157), exact head
`a613fdfcd9bbc238e7a988d86b105d779af36cf7`, directly above #156. After
rebasing, four CLI cases and an independent SRT/WebVTT byte, permission,
no-replace, schema and full-manifest smoke passed; the production governor
was unchanged. None of these drafts has formal platform approval, online
acceptance or a merge, and local export does not prove player synchronization.

## Unverified integration: cached-challenge compatibility

The current integration candidate adds a durable mailbox for a
challenge discovered in cached content. The older governor in the root worktree
does not read that mailbox. A candidate process and an older process sharing one
account governor therefore cannot be assumed to enforce the same challenge
observation before a request. Do not mix such binaries for campus access; a
coordinated rollout and an independent compatibility decision are still needed.
The candidate has completed an offline build but not behavioral tests or a
fresh exact-source review of this compatibility boundary. This is not online
acceptance.

An independent source review also found a conditional legacy migration hazard:
the pre-patch integration lock explicitly unlocks in the owner process, while
a forked child can retain an old lease snapshot whose completion path does not
re-read the on-disk format. A version bump alone therefore cannot prove that
all old writers are fenced after the parent unlocks. This is a source-derived
process transition, not an observation that such a child exists. A proposed
format cutover would additionally require verified old-actor quiescence, the
same pinned directory and account lock, known outcomes, and explicit approval;
neither that migration nor an authentication resume has been performed.

## Unverified response-admission candidate (2026-10-28)

Source review found that several service readers discarded `Set-Cookie`
before screening body output. A newly issued opaque cookie value could then
escape through a normal data field or raw fallback; this is a synthetic
source-level finding, not an observed campus response. The candidate service
readers without a cookie jar now refuse such content on any `Set-Cookie`
header. This intentionally may refuse benign cookie rotation or preferences;
it neither adopts the cookie, retries, refreshes authentication nor treats
issuance alone as a confirmed challenge. The department Git-source transport
uses the same header refusal and reuses the learning-material privacy screen
for abnormal source evidence, not for identity-verified teaching-file content.

The candidate also compares submitted credentials against supported base64
and percent/form encodings and completes response admission before releasing
the original shared request lease. Actual HTTP authentication refusals,
challenge observations and `Retry-After` remain independent settlement facts.
These source changes are not a claim to recognize arbitrary secret encodings.

iHome cache version 4 and department cache version 2 mark the new admission
boundary. Earlier files omitted cookie-issuance evidence and cannot establish
that their bodies are safe to publish. The candidate preserves those files
but refuses replay; it does not delete them or automatically make a new
request. Independently recognizable cached safety refusals remain observable.
Operator-controlled private recovery or a separately authorized retrieval is
needed; old cache bytes are not silently relabelled as newly reviewed data.

The integration passed a locked native build and an offline
help/schema/capabilities smoke before later source changes. Focused synthetic
tests have since passed, but the full test suite and a renewed review of every
changed source remain incomplete. Previous standalone compiler probes
and approximate algorithm harnesses were not compliant native proof and must
not be used as acceptance evidence. All nineteen pending capability criteria
remain pending in `acceptance.json`; no new authentication, media request,
session resume, rights approval or campus mutation is asserted here.

The first guarded native offline build on this candidate did acquire both
locks as UID1000 and compile the actual crate, then failed with four errors:
a physics privacy match returned `Option` where a statement required unit;
the learning identity stored a static error code in an owned-string field;
a borrowed entry slice was borrowed again for iteration; and a JSON privacy
scanner called `find` through an immutable iterator. Those four sites were
corrected, with static error codes retained by reference. The subsequent
guarded attempt returned 75 before Cargo started because the shared heavy
slot was occupied again. A later guarded build compiled the library but
failed in the CLI's oversized schema `json!` expansion. That command map was
replaced with ordinary map construction, without raising macro recursion
limits, and a now-unused local helper was removed. The next attempt again
returned 75 before Cargo started. A later guarded offline build succeeded as
UID1000 with a worktree-owned target and one compiler job. The resulting native
binary's help and 33-command schema ran successfully; its full 51-capability
manifest matched `acceptance.json`, the recorded 87 build inputs stayed stable,
and the production governor snapshot was unchanged during the offline smoke.
Subsequent full-test attempts returned 75 before Cargo started because another
project held the shared heavy-work slot. A later attempt reached Cargo but
failed to compile two privacy assertions because `net::Error` does not implement
`Display`; those assertions were corrected to inspect its `Debug` fields.
The next attempt failed while compiling the library tests with a 7,471,120-byte
allocation failure under the 2 GiB address-space limit, before any tests ran.
A retry with incremental compilation disabled and test debug information
stripped also failed in LLVM from memory exhaustion while compiling the library
tests. The same process limit and shared locks were retained. A separate CLI
integration run executed 26 cases: 25 passed and the baseline privacy case
failed because the chosen temporary path had group-writable workspace
ancestors, which the existing baseline safety policy correctly rejects. That
failure is retained. A further library-test compilation with 256 codegen units
also exhausted the 2 GiB address-space limit before any library test ran; the
full library suite has not passed.

A separate synthetic `enrol` CLI regression ran under both locks and failed
all six groups before repair: missing MIME challenge, malformed charset,
credential metadata, late stylesheet, popover/button cues, and quoted MIME
parameters. Each group stopped at its first failing assertion. These are
offline consumer observations, not a campus response or online acceptance.
After the first repair those six groups passed, while two new regressions
failed: an invalid tag opener hid a late stylesheet from the tail scan, and
adjacent button text nodes hid a challenge cue. A further source review also
identified the need to carry cookie-issuance and credential-echo facts from
the unbound Session before admitting structured responses. After a subsequent repair,
ten synthetic CLI admission cases passed under both locks. A later
bogus-comment regression also passed after repair, but two adjacent cases
still failed: an invalid end tag and foreign-content CDATA could obscure a
late stylesheet. These are retained synthetic failures, not campus responses;
no new campus request or authenticated Session was exercised.

A temporary, default-off offline proof feature then linked the ordinary
library into selected integration tests rather than compiling the full unit
test crate. Under the same locks and 2 GiB limit, all thirteen HTML/`enrol`
CLI cases passed. The other targets reproduced four separate defects:
learning transport/cached evidence (three failures), iHome literal-JSON safety
facts (three), Smart reserved-marker admission (one), and electricity source
scalar semantics (two). Their ordinary-data and independent safety controls
passed. After the corresponding repairs, the five selected targets passed
27 cases: 13 HTML/`enrol` CLI, 5 learning transport/cache, 4 iHome,
2 Smart and 3 electricity cases. A separate temporary native consumer also
exercised those four response-admission families; its source remained stable
and the production governor was unchanged. These are synthetic observations,
not fresh service observations, a default-feature full-suite pass or online
acceptance. The first temporary proof interface was then removed.

Independent source review subsequently identified two additional learning
cache defects. A fixed synthetic loopback run reproduced both: an existing
rejected original made a later degraded response fail with `cache_error`,
and a cache reader observed a newly published two-link inode as
`corrupt_cache`. The same guarded run passed three separate `enrol` scenarios
using a synthetic Session: privacy facts gate probe/list/verify, and
challenge, Retry-After and incomplete-body facts survive settlement. The
Session supplies those facts directly; it does not validate real response
headers, credential echoes, authentication or application binding. After the
postcondition fixture was strengthened to use the exact target, all three
scenarios passed again; an exact target in this synthetic HTML still cannot
establish an authoritative selected-course postcondition. A candidate atomic
no-replace cache publication and separate rejected-original naming were added
after the red run. Two guarded reruns returned 75 before Cargo started because
the shared heavy-work slot was busy; a subsequent run passed both learning
cases, preserving the v1/v2 rejected originals and reading the new evidence.
Those assertions were then strengthened to require the publication callback
and compare retained metadata and repeated originals. After a further cleanup
change, both strengthened cases passed. Neither actual target-name exhaustion
nor directory-fsync failure was exercised. The second temporary proof
interface and its example were removed after the fixed native consumer ran;
permanent unit and actual-CLI regressions remain.

A separate synthetic encrypted Boya response with a literal `token: null`
reproduced an unnecessary privacy fallback; a non-null token remained withheld.
The historical UBAA response model includes a nullable token but is not proof
of the current campus contract. The candidate now exempts only a `token` member
whose JSON value is null, while retaining the other credential checks. Two
post-fix tests passed, including escaped null and non-null credential controls.
A scoped source review found no new concrete issue; the fixed synthetic native
consumer also exercised the repaired path.

Fresh independent review found two more synthetic privacy defects: evaluation
could project a numeric submitted-cookie value as a task total, and shuttle
could project a percent-encoded CSRF value as visible text. Each was reproduced
before repair. The evaluation admission case and two shuttle CLI cases then
passed under both locks, including ordinary-data and encoded/normalized-value
controls. A further source review found that partially percent-encoded secrets
containing a literal `=` can evade the shared form-field matcher. The new
whole-candidate decoding passed two evaluation and three shuttle cases after
repair, including literal separators, plus-sign interpretations, malformed
escapes and invalid UTF-8. The specific mixed-separator pre-fix runs did not
start because the shared heavy slot was busy; that earlier finding is
source-derived, not an executed red test. Two scoped source reviews found no
new concrete issue. A separate fixed synthetic native consumer exercised both
paths; it did not exercise production transport or authentication. These
fixtures are not observed campus responses.

Two additional source reviews found that submitted credentials can reappear
after JSON scalar projection even when the wire bytes do not contain the same
spelling: a decrypted Boya boolean or number, and normalized numeric fields in
Checkin, Drive and Smart. The fixed synthetic consumers reproduced all four
families before repair. A shared bounded scalar matcher now checks the actual
JSON output spelling; Smart checks its projected numbers before releasing the
original lease. The subsequent guarded run passed 39 cases across ten targets,
including ordinary, denial and raw-fallback controls. Independent review found
that local fallback/status metadata, and then synthesized nulls for missing
Boya fields, could be mistaken for source credential echoes. Those failures
were reproduced and repaired without exempting explicit source nulls. A
separate allocation regression reproduced per-number Running credential
re-encoding and passed after the length guard. A separately launched fixed
synthetic native consumer passed against stable selected source inputs. Direct
admission fixtures do not establish transport behavior or actual lease
settlement; these are not campus disclosures or online acceptance. Scoped
independent source reviews found no further issue.

Four physical-experiment replay cases also passed through the actual CLI, with
operator-supplied HTML and no network. Independent review then identified a
long numeric HTML reference that hides private vocabulary and a quoted-pair
charset that is rejected despite spelling UTF-8. Two CLI cases reproduced
those failures and passed after repair. Four further CLI cases demonstrated
that numeric and legacy named references without semicolons can hide private
markers, including references that decode to printable characters. Further
review and CLI red tests found discarded source content, inert `srcdoc`,
private labels in comments and an unbounded first DOM parse. After repairs,
twenty CLI replay cases passed, including unconsumed-reference controls,
discarded text, nested `srcdoc`, 100,000 attributes in one refused token and
64 sets of 512 short attributes. Independent source reviews found no further
issue. Ambiguous provenance or the configured 1 MiB/4,096-candidate limits
withhold output; the attribute HashMap is not a worst-case-linear guarantee.
This is not a claim that every HTML source is supported. The physics service
remains offline and unbound.

## Native verification still open (2026-10-30)

The integration source was checkpointed locally as
`9cbc4cdf08deb294c20451a1e22f9b32cf23b8ea` and rebased onto the subtitle-export
layer as `3f4f0345246cb22b1a815c562a9f4548d279eaa2`. It is published as a
[Gitea draft](https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/158),
but has not been deployed.
A subsequent locked, offline default-profile build acquired the shared
heavy-work slot but failed while creating encoded library metadata with
`Cannot allocate memory (os error 12)` under the unchanged 2 GiB address-space
ceiling. All 98 recorded build inputs remained unchanged. No current binary
or full-library-test pass is established by that run. The test-only server
dispatch deduplication has not yet established that the full library suite
fits within the existing limit.

A separate guarded host probe attempted mpv and VLC with synthetic local
media and subtitles. Both CLI invocations exited 2, producing no replay
receipt or screenshot. The probe placed its files below group-writable OMP
ancestors, which do not satisfy the replay path policy, and failed to retain
the child diagnostics. Its overall zero exit was a probe-classification bug,
not successful playback. The corrected probe uses an exclusive directory
below the passwd home, preserves synthetic diagnostics and requires both
successful CLI receipts and all expected player captures. A completed
collection will still require visual inspection and will not establish
campus media rights, physical audio or live playback.

Independent review of the published documentation prefix identified a
conditional CI lock-path mismatch. The candidate now requires the effective
UID's passwd home to be `/home/ezra` before checking the canonical mounted
lock. This matches `scripts/cargo-locked`, which derives its lock from passwd
rather than `HOME`. No successful internal CI run is claimed.

## Gitea primary restoration (2026-10-30)

The development primary is the private, native
[`ezra/buaa-cli`](https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli)
repository. The formerly registered Gitea repository ID was no longer
available. The existing operator recreated and enrolled the native repository
as ID 161, leaving both prior backup repositories intact. Before restoration,
the operator cache's 138 refs were saved in a verified private Git bundle;
afterward all 69 previously recorded primary refs were present as equal or
descendant refs. The shared Git `origin` now names the Gitea HTTPS URL; the
worktree uses a repository-scoped deploy key and a pinned SSH host key for Git
transport. GitHub remains a separate downstream, not the development origin.

The existing Gitea workflow is scheduled daily at 19:30 UTC, or 03:30 Beijing
time. One manual execution of that same workflow,
[run 641](https://doesvm.icefish-exponential.ts.net:8444/ezra/gitea-primary/actions/runs/641),
completed successfully and used the existing dedicated GitHub credential.
Its receipt reported 72 equal refs and two new downstream branches, without
conflicts or force pushes. Independent readback matched Gitea and GitHub for
`main` and both newly published development branches. This verifies that
manual invocation and those refs; the next automatic scheduled invocation has
not yet occurred. Every Gitea branch and tag is eligible for publication to
the public GitHub downstream on a successful sync, including draft and
checkpoint branches. Downstream-only refs are preserved, so deleting a Gitea
ref does not automatically retract its published counterpart. Do not commit
private source evidence or credentials to any branch.

The two development pull requests are Gitea drafts; their numbers and reviews
are independent of GitHub pull requests and native `gh stack` metadata.
Neither host's checks or approvals automatically transfer to the other.
Synchronization is not evidence of a successful build, merge, login or online
acceptance.

## Drive source-contract boundary

Pinned public clients describe candidate AnyShare OAuth, listing and transfer
requests, but they are not proof of the campus deployment or account rights.
[Pansh](https://github.com/Fucov/Pansh/blob/a17516ff8c058bc5682727d45845d6820f426a66/src/pansh/api.py#L288-L324)
uses `ondup=1` as its default and `2` for rename; a separate
[AnyShare client](https://github.com/isHarryh/AnyShare-Unofficial/blob/c1b6e265ea82d227c233272d49832825b28bd5ad/anyshare_unofficial/types/enums.py#L34-L39)
labels `1` as rename and `0` as forbid. Neither mapping is admitted as the
current BUAA contract. The candidate rejects a contradictory `ondup=3` with
`overwrites=false`, but its remaining structured preview only binds the
caller's intent; it does not verify remote collision behavior or a resulting
name. Commit is blocked. Directory-list request construction and token
exchange also remain blocked pending their own source and security contracts.
No online drive operation or mutation is established by this research.

## Observation correction and CI migration prerequisites (2026-10-26)

The bounded browser observations are archived in
[`CAS-LOGIN-PROTOCOL.md`](CAS-LOGIN-PROTOCOL.md) and
[`SSO-LOGIN-PROTOCOL.md`](SSO-LOGIN-PROTOCOL.md). They show a successful browser
redirect sequence and the parent form's six-field order. They do not establish
the cause of the CLI callback 500: the original error body and per-request
timestamps are absent, and the deployed ticket lifetime was not observed.
The upstream default is a hypothesis input, not the deployment's configuration.
Browser HTTP 200/application code 200 also does not satisfy the CLI's required
selected-lesson verification, which remains unpassed.

An uncommitted candidate that removed required account protections and changed
cache/refusal semantics was withdrawn before publication. The Rust source,
account rules and capability catalog were restored to the previously reviewed
`74b501e44bc7d4d8268b3fd20bb22d07d5db607f` baseline. Fresh original-runtime
verification passed formatting, locked offline build, all-target tests
(541 library passed, three ignored; 21 CLI passed), strict all-target clippy,
whole 51-capability equality and actual local authorization/unknown-field
refusals. Source and original account-state bytes remained unchanged. This
proof made no authentication invocation and is not online acceptance.

The owner requested internal Gitea development/CI with GitHub used for review
and releases rather than CI. The installed `gitea-primary` operator performed
the takeover with the supported migration path. The previous pull mirror was
retained as `ezra/buaa-cli-pull-backup-20261026T141050Z` rather than deleted,
and the repository is now the native `ezra/buaa-cli`, registered for the
non-force per-ref fast-forward sync with the source as the checked downstream.
The first migration request failed while fetching GitHub issue-comment
metadata, because the container's DNS does not resolve the GitHub API host
even though the host does. The Git objects and every branch had already
arrived, and the operator's re-run completed the takeover and the
registration. No repository was deleted or recreated, and no history was
forced.

The native repository's git endpoint was proved by a real clone whose fetched
head was the current `main` commit. The clone authenticates with the
installed operator credential adapter over HTTP. That adapter is a local
reader of the credential file rather than a broker, so the build job must
not use it: doing so would hand the credential file to the build processes.
The source is therefore fetched in the operator's protected context and
handed to the job as a verified, credential-free tree whose identity the job
re-checks against the admitted SHA.

That hand-off is not provided by the current operator tooling, which performs
the takeover, the metadata import and the daily sync but does not prepare a
source tree for a job. The lane therefore verifies the tree it is given and
fails with a clear message when the required delivery has not happened.
Delivering that tree without exposing the credential file to the build
processes is a remaining prerequisite and is not claimed as done.

The internal lane itself is not yet a working gate. It is dispatched manually
against an operator-admitted exact source SHA, uses the canonical global build
gate and one compiler job, and builds with Cargo's offline mode against a
fresh exclusive target. It does not provide kernel-level network isolation:
the job image and build environment must deny egress if that boundary is
required. The job still needs the operator-prepared source tree, the
canonical lock and cache mounts to be present, the job image's tool and
cache coverage to be verified, and one successful admitted run to be
observed. Draft workflow files and a runner's capacity setting do not prove a
working internal gate, and no successful internal CI run is claimed.

The reported proxy quota consumption remains a separate investigation. Failed
endpoint probes, cache sizes, sparse-file logical lengths and repeated file
descriptors cannot attribute the reported 700 GB to this project or to a
particular application. No such attribution is established here.

The dependency-network facts that were measured are recorded here so they are
not re-derived. The public crates.io CDN does not answer from the build
network, while a mainland registry mirror answers in under a second. The
original runtime's Cargo cache holds the project's complete locked set of 201
crate archives under the mirror's source namespace, and an offline metadata
resolution against that cache succeeds with no download. The same cache also
holds 223 archives under the upstream namespace, including seven packages the
lock file does not require, so the two namespaces overlap rather than
partition the dependency set. With a mirror declared only under a separate
source name, the lock file continued to resolve against the upstream registry
and the offline resolution failed. The project configuration therefore
replaces the canonical `crates-io` source with the mirror, which makes the
already cached mirror namespace the one the lock file resolves against. The
cache directory is keyed on the registry URL rather than on the source alias,
and the same replacement name the prebuilt job image uses is kept so both
seats describe the registry identically.

Container image tags were inspected for duplication: several tag names resolve
to one image identifier, so extra tags consume no additional layers and no
additional transfer. Redundant tags were removed; image size was unchanged.

## Current integration and authentication boundary (2026-10-26)

PRs #125, #126, #127 and #128 are merged; native Stack #129 closed after
their integration. The observed `main` commit is
`004cf2f72953d48bdeed810582b482f398825144`, with tree
`0d3750357ee403c1f82a7700aa3dba3abe7a0cb6`. Every newly restacked head
received independent exact-head/base source review and two successful native
offline CI checks before its non-bypass merge. Ordered merge parents, trees,
PR states and the actual main ref were independently read back. Earlier
review-pending statements below describe their historical snapshots, not
these merged heads.

The final source head `b0351ba20441bc2734a9d5d307b17378bb50a415` built in
the original UID1000 runtime under the shared heavy-work and Cargo locks.
Its complete embedded capabilities matched the manifest. Actual CLI consumers
passed GPA schema/runtime boundaries, actionable errors and timestamp bounds,
catalog/search authorization, permission exit 5 versus malformed JSON exit 2,
and owner-only idempotent baseline saves. Source, binary and production
governor bytes remained unchanged during this offline proof; it made zero
campus requests and zero authentication attempts. The intermediate schema
layer's formatter failure, bounded-linker allocation failure and invalid
throwaway help-wording assertion remain failures, not successful proof.
The formatter was repaired by a normal fast-forward append; the completed
arena-bounded gate and resumed actual smoke passed without weakening policy.

**Online authentication is still not passed.** Before those merges, one
deliberate governed attempt on session module
`0980d3e277fa3327b438f77369f0bd4d0f714b05397844ead514f461fcdadf29`
again recorded SSO GET 200, credential POST 302 and classroom CAS callback
500. No session or positive application probe was established. The original
callback body was not retained, so the cause remains undetermined; neither
password rejection nor a cookie defect is established. The safety latch is
set, the one-shot authentication arm is consumed and no request is pending.
No automatic retry, ticket replay or alternate governor was used. Issue #124
remains open. Earlier failed observations below remain part of the history;
merging these fixes does not establish live playback, dual-player rendering
or subtitle synchronization.

## Governed public online verification round (2026-10-23)

Campus egress from this host is reachable again: `classroom.msa.buaa.edu.cn`
resolves to the internal address, the TCP connect succeeds and the TLS
session verifies `*.msa.buaa.edu.cn`. The earlier "TLS severed at the network
edge" observation is no longer current for this host and is not rewritten in
the historical receipts.

Using the earlier candidate CLI and the production shared governor, fifteen college
source surfaces were re-read with `--refresh` and produced fresh
`miss`/`revalidated` observations with HTTP 200, byte counts and body
digests: aviation, beijing, bme, cst, dept3, h3i, iai, ic, iiif, mse, rse,
scse, shenyuan, ygy and zfai. The historical sweep retried some failed
requests and honoured local pacing refusals. Earlier failures remain failures;
only admitted final responses count here. These root-page observations do not
complete department material catalogs, notice bodies or all-college coverage.
HSS did not complete its network interaction and EE remains
surface-only because its HTTPS certificate names do not match; both stay
recorded as failures.

Some later selected college surfaces were **not** requested: a rejected classroom
authentication latched the shared account-safety state, so every
account-scoped request was refused locally with exit 4 before any network
request. These refusals are separate from the earlier surface observations.
No parallel account key or TLS bypass is authorized. Subsequent deliberate
authentication resumes do not erase the refusals or establish the missing
adapters for ihome and department materials.

## Governed classroom session acquisition

Online acceptance is **not passed**. The retained 2026-10-25 attempt on
module `2ccfb0dbba267ede0f4b241ec8644494b6fd8c724ef10a7123ee1e0e34e3a10c`
recorded initial SSO HTTP 200, credential POST HTTP 302, then classroom CAS
callback HTTP 500. No classroom session or positive selected-lesson response
was established. This supersedes earlier guesses that the attempt stopped
before password submission; the sanitized attempt trail proves the POST.

The asserted URL-cookie cause was incorrect: the original RFC 6265 octet
ranges already allow colons and slashes. Synthetic Chromium acceptance of a
URL-shaped value does not prove the CLI dropped it, nor explain callback 500.
The unnecessary cookie grammar relaxation is withdrawn. The callback failure
cause remains undetermined; a redirect alone does not verify account identity
or application access. No callback ticket is replayed to recover missing
response content.

On a known safety latch, deliberate operator-authorized resume is required;
the offline arming receipt is never login success. Existing cooldowns,
Retry-After and scheduling floors remain effective. A fresh Agent must
actually establish and use the session before login UX can pass acceptance.

The isolated UID1000 offline gate for module
`0980d3e277fa3327b438f77369f0bd4d0f714b05397844ead514f461fcdadf29`
passed 129 focused session cases, 540 library cases and 19 CLI cases, with
three existing workers ignored. Strict all-target Clippy, formatting, build,
whole native capabilities equality and actual CLI authorization/secret-field
refusals passed. Source and production governor bytes remained unchanged;
this gate performed zero campus requests and zero authentication attempts.
This gate preceded its evidence-only manifest update. The earlier scoped
diagnosis/cookie review did not cover all root changes: a broader review found
a missed challenge-only page and two nonfinite CSS arithmetic defects.
The page regression failed before repair; two mathematical color regressions
also failed after native Chromium150 FormData corroboration. All now pass.
Challenge observations remain available when the credential form is refused,
using one bounded DOM parse and the production settlement path for both
credential-free readers. Independent approval of the exact publication head
is a separate gate; this offline receipt provides neither that approval nor
online acceptance or a callback failure cause.

The subsequent full non-color review of head `5e7fe238` requested changes:
redirected/unexpected HTML could conceal active challenges from settlement,
non-successful authentication-kind inspection could misreport the retained
latch, and an image's non-applicable `form` attribute could veto admission.
All three targeted regressions failed before repair. Eight targeted offline
regressions now pass, including existing MIME/shadow-root and table ownership
boundaries. Native Chromium150 FormData also confirms the image behavior.
Settlement now returns its actual durably saved latch under the same lease;
no account-safety policy is weakened. Production governor bytes remain
unchanged, with zero campus requests or authentication attempts. This focused
receipt does not approve the source; a new full gate and exact-head review
remain due.

The broader native color oracle now contains 1,940 synthetic Chromium150
FormData cases. Its initial comparison exposed 87 real mismatches; literal,
Hypot/Log/Round and precision repairs reduced those to zero on module SHA
`d78d3478886c5f0556d87cb186c498107b89ed49c1abefbe8f00ecf585a65134`.
HSL uses the observed float32 conversion/quantization path; Display-P3 uses
the observed XYZ D50 and inverse-transfer path rather than an idealized
neutral-preserving matrix. A supplemental nonfinite batch exposed and fixed
P3-specific NaN loss without changing other callers' parser policy; all
thirteen permanent assertions pass. The review's pow-NaN and ideal P3-neutral claims
were withdrawn after native contradiction; literal overflow remained valid.
An intermediate percentage-multiplication candidate's 119 HSL failures are
retained, not hidden. The final packet comparison passed with unchanged
source/packet and production governor bytes and zero campus/authentication
activity. Scoped independent review required removing its temporary comparison
consumer and the obsolete decoder; both are removed without lint
suppression. The first complete candidate passed its tests but failed strict
Clippy `manual_clamp`; the expression was corrected without an exemption and
the complete gate rerun passed. Fresh exact-head review remains; this is
neither release approval nor online acceptance.

Latest local follow-up (2026-10-25): the six reviewer10 findings were reproduced
in the original UID1000 devcontainer: 83 session cases passed and six failed.
Hidden `_charset_` now uses UTF-8; expired cookies cannot consume replacement
creation positions or evict fresh sessions; range defaults and local decimal
ties remain exact with distant bounds; foreign script/style descendants retain
document ID membership; dirname directionality includes noscript without
changing challenge/prose exclusion. All 89 session cases pass on module SHA
`f0b3cae7618d4de73f67c18eed4e7d286527565f0651b9ce0fe9a8ea78d52a00`
and shared HTML SHA
`7dccb9d250cbbc5a25395a12b1c113c366f5d89e7d5f30e73380730c8f2bcc64`.
The focused run held the shared heavy/Cargo locks, used the worktree-owned
target, checked source stability and left production governor bytes unchanged.
It made zero campus requests. Full current-source gate, fresh independent
approval and governed authentication remain pending; no new session is claimed.
The first full gate stopped at strict clippy `manual_contains` in the existing
auto-dirname credential test, before complete tests or build. Candidate
`e60722abe90c41576a04a9b72eeb58fc509a542f54d7f56dfd15518ab1a7a388`
changes only that assertion to equivalent `contains`; its complete gate and
independent review are separate from the earlier focused proof.
After the formatter required that assertion on one line, module SHA
`b8506ce46d6542354e6707020a6ef33c2296e09a4ff527b2759fc80e40514046`
passed the complete original UID1000 gate: 500 library and 19 CLI cases, three
existing ignored workers, strict all-target clippy, fmt check, offline build,
actual native help/schema/refusal smoke and whole-manifest equality. Source
and production governor bytes remained unchanged, with zero campus requests.
Fresh exact-source independent approval and governed authentication remain
pending; the previous Clippy/format refusals remain retained.
That exact b8506ce4 source then received REQUEST_CHANGES for modern HSL/HWB
channels and hard-wrap textareas. Native Chromium150 about:blank FormData
confirmed modern numeric channels, unbounded HWB ratios and width-dependent
textarea breaks. It contradicted the review's modern-HSL saturation example:
both modern and legacy `hsl(15 200% 50%)` spellings retain `#ff4000`, not the
claimed `#ff0000`; that clipping was not changed. Three new regressions failed
before repair (89 passed), then all 92 session cases passed on module SHA
`f920d447cb9e85decdf741b15befe8c8b3a116edb1af51daf92ec073b4c2c561`.
Nonempty hard-wrap textareas now require interaction review instead of guessed
submission values. Governor/source bytes stayed stable and campus requests
were zero. The f920d447 snapshot subsequently passed its own complete native
gate: 503 library and 19 CLI cases, three existing ignored workers, strict
clippy, formatting, build, native CLI smoke and complete manifest equality.
That is not independent approval: the exact-source reviews requested changes
for absolute CSS math channels, Lab-family lightness clipping, XHTML parsed
under HTML rules and unsupported declarative shadow roots. Native Chromium150
confirmed all four differences without campus access. Four consumer regressions
then failed on the reviewed implementation (92 passed, four failed). The
integrated repair passes all 98 session cases on module SHA
`eb3710e4481e3dbfc5794204ce0d4c7c61ba059d3663183b89ef35497b836f5d`,
including native constant/non-finite math boundaries. Earlier integration
syntax and legacy comma-field failures remain retained. The passing run held
the shared heavy/Cargo locks, verified stable source and unchanged governor,
and made zero campus requests. This changed source still requires its complete
gate and independent approval before the prepared one-shot authentication
operation can run.
The subsequent c59eeccf snapshot passed its complete gate (509 library and
19 CLI cases, three existing ignored workers), but independent review still
requested math-domain/token/EOF corrections and parent-only optgroup
disabledness. Synthetic Chromium confirmed six repair groups and rejected the
review's percentage-atan2 example: that color remains invalid/black in the
observed browser. Six new regressions failed before repair (98 passed), then
all 104 session cases passed on module SHA
`51236e457683760030a4475057df092b0ea6fb9a7260014db5ed947f3156ad94`.
Source/governor stayed stable and campus requests were zero. This newer module
then passed its own complete gate: 515 library and 19 CLI cases, three existing
ignored workers, strict Clippy, formatting, build and native CLI refusal smoke.
The embedded capabilities manifest matched the complete current manifest.
Complete scoped review of that source returned REQUEST_CHANGES: four math
boundaries (dimensional default round intervals, rounding/modulo signed zero,
and comment-versus-additive-whitespace syntax) and four form-admission
boundaries (submitter overrides, active document bases, effective encoding,
and parser-associated nonancestor controls). Synthetic Chromium150 confirmed
all eight. The last case requires an active browsing context: iframe srcdoc
includes the table-associated hidden field, while inactive DOMParser omits it.
Neither observation is substituted for the other. Repairs and a new exact-source
gate/review were required. Eight new regressions produced 104 passed/eight
failed before repair, then all 112 session cases passed on module
`b94577fe768766d780b1e0fc096e33151dd569fa905c99240a4a94155256f31d`.
The repair refuses unsupported source metadata and all relevant table insertion
containers while retaining ordinary cell/caption forms and explicit external
controls. Native boundary observations also confirm nearest-rounding exact
multiples and near-half values, plus leading/trailing functional-color comments.
Source and production governor stayed unchanged during the focused proof;
campus/authentication counts remain zero. The new complete gate passed 523
library and 19 CLI cases, with three existing ignored workers, strict Clippy,
format check, explicit build, native CLI refusal smoke and whole-manifest
equality. Independent review remains pending and the prepared authentication
remains unstarted. [Issue #124](https://github.com/cyjin-yl/buaa-cli/issues/124)
tracks the owned publication and still-unverified online acceptance; creating
the issue is not a session or merge claim.

A newly authorized original-runtime attempt on 2026-10-23 stopped with
`unreviewed_login_interaction` after exactly one initial SSO HTTP 200. The
inspected code path and retained trail place refusal before password submission;
no session was stored. This is not evidence of a wrong password or a confirmed
CAPTCHA. The original latch is retained and the response did not identify the
rejected control. The new `recordings session inspect --online` entrypoint
therefore exposes bounded, value-free first-rejection metadata through the same
governor without submitting credentials. Its 26 session tests and original
UID1000 build passed, and native help/schema/manifest plus invalid-input CLI
smoke left production governor bytes unchanged. Its online read and the complete
current-source gate remain separate, not-yet-claimed observations.
Independent transport/lease and HTML/metadata privacy source reviews reported
no concrete findings; these are not exact-head publication approvals. The full
gate's first admission returned global heavy-slot busy exit 75 before execution.
The shared lock is preserved, and no second instance or lock bypass is used.
After that holder released the slot, the diagnostic-only source passed strict
all-target clippy, fmt check, offline build, 436 library and 19 CLI cases (three
existing library workers ignored), complete native manifest readback and exact
source/governor stability. One deliberately authorized, credential-free initial
page inspection then returned HTTP 200: its first rejected control was an inert,
non-required text input named `type`, with no response or active-control
challenge signal. Zero passwords were submitted and the latch remained set.
The follow-on repair recognizes only existing noninteractive POST protocol
fields with reviewed values; that newer source requires fresh proof and review.
A complete hash-bound independent review of the first protocol representation
repair found that the conservative challenge-visibility predicate was unsafe
as positive admission evidence for malformed or overridden CSS. A focused
offline regression reproduced the failure before repair and passed afterward.
That intermediate own-inline-style repair passed a complete offline gate but
its full-source review found further CSS bypasses: challenge buttons and a
stylesheet `!important` override. Both were reproduced before repair. The
intermediate exception required the protocol control's own `inert` attribute; CSS
cannot prove this exception, and uncertain marked challenge controls require
review even when button-like inputs would otherwise be allowed. The same
review found cookie deletion suppressed by invalid Expires and credential-bearing
redirect paths in receipts. Both are repaired with seeded-cookie and actual
receipt readback regressions. That intermediate source passed all 31 session
cases and a full 441-library/19-CLI offline gate, but its hash-bound review
found label-only challenge actions, RFC cookie-date deletion, and query-key
credential retention. All three were reproduced before repair (four failing
cases). That intermediate source passed all 34 session cases, including split-node
labels, calendar-invalid deletion refusal and actual receipt byte readback.
Its 444-library/19-CLI gate passed after an equivalent test-only Clippy assertion
correction, but the complete-source review found three further edges: input
caption whitespace, negative Max-Age underflow and source-controlled names in
ordinary output. Four regressions failed before repair (34 passed), then all
38 session cases passed. The repaired source passed a complete 448-library/19-CLI
offline gate with three existing ignored workers, strict clippy, fmt check,
native build, equal whole manifest and stable source/governor bytes. A fresh
complete-module and shared-dependency-excerpt review approved that exact source
snapshot with no findings; this is not an exact-head publication approval.

One subsequent deliberately authorized, credential-free initial-page read
returned HTTP 200 and 11,403 bytes. It still required interaction review for a
non-required text input labelled `type`, with its inline-hidden/inert summary
flag true and no response or active-control challenge signal. That summary
does not prove the control's own `inert` attribute or reveal its value. No
password was submitted or session stored, and the safety latch remained set.
The inspection command is exercised online; admission of the actual login form
and positive selected-lesson authentication remain unfinished implementation
work, not evidence of a wrong password or confirmed CAPTCHA.

The follow-on diagnostic source adds only `own_inert` and
`reviewed_protocol_value` booleans to explain that refusal without returning
values or changing admission. It passed 39 session cases and a complete
449-library/19-CLI offline gate. Its complete source review then found arbitrary
MIME-subtype retention in inspection output. A serialized-output regression
failed before the MIME projection repair (39 passed, one failed); all 40
session cases passed. The MIME repair maps recognized types to fixed labels
and everything else to null. That exact MIME source then passed the full
450-library/19-CLI native offline gate (three existing ignored workers), strict
clippy, fmt check, build, whole-manifest equality and source/governor stability.
A complete hash-bound source review approved that snapshot with zero findings.
Its one deliberate credential-free online read returned HTTP 200/11,403 bytes:
the first refused `type` text input had `own_inert=false` and
`reviewed_protocol_value=true`, without response or active-control challenge
signals. No password was submitted and the latch remained set.

The operator subsequently authorized all ordinary source-form fields, replacing
the inert-only protocol exception rather than adding another type-specific
exception. The current implementation collects successful source controls,
preserves names/values/order and duplicate noncredential names, and overrides
only the protected username/password values. Action/method live outside the
field namespace; no protocol defaults, page-script execution, local-file reads
or automatic choice/consent are added. Challenge signals, credential-role
integrity, the pinned SSO destination, one deliberate authentication attempt,
production governor spacing and fresh selected-lesson verification still gate
the flow. The first general-field snapshot passed 41 session cases and a full
451-library/19-CLI native gate with three existing ignored workers, strict
clippy, fmt, build, whole-manifest equality and stable source/governor bytes.
Its independent complete-source review requested four concrete repairs:
associated challenge labels, first-document-ID form ownership, listbox default
choices and radio-group source checkedness. Actual Chromium FormData/ownership
observations corroborated the choice/ownership behavior. All four new regression
groups failed before repair (41 passed), then all 45 session cases passed after
repair with unchanged governor bytes and zero campus requests. The repaired
source shares one owner resolver across selection/collection, treats associated
challenge labels as interaction review without exposing text, and never invents
a listbox choice or submits an obsolete radio. Its complete native gate, fresh
source review and one governed authentication remain separate pending gates;
the earlier passing snapshot was not approved. The next complete-source review
found one further boundary: an absent or non-HTML initial response MIME could
still be parsed as a login form. Its regression failed before repair (45 passed,
one failed). Authentication and inspection now share the fixed MIME-label
projection and require HTML/XHTML before form parsing; inspection otherwise
returns only safe metadata with `unexpected_login_content_type`. All 46 session
cases passed after repair with unchanged governor bytes and zero campus
requests. The following complete-source review found that final-response
analysis still required the original credential/execution form, allowing a
secondary label-only challenge to disappear into a default result. It also
found that an empty Set-Cookie value retained the previous token. Two consumer
regressions failed before repair (46 passed), then all 48 session cases passed
after repair. Final-response scanning now covers controls and associated labels
without requiring a credential form, keeps a separate remaining-password veto,
and refuses analysis errors. Empty cookies replace the old value and round-trip
through actual request headers and private storage; Max-Age deletion is unchanged.
The governor remained byte-identical and no campus requests occurred. That
48-case source then passed the full 458-library/19-CLI native gate (three ignored
workers), strict clippy, fmt, build, actual inspection-refusal CLI smoke,
whole-manifest equality and source/governor stability. Its fresh complete-source
review requested three further repairs: canonical cookie identity across
host-only/Domain transitions, final-password detection independent of disabled
submission state, and review-only classification of auxiliary label cues.
The next complete-source review found five more boundaries: HTML-typed lesson
probes were not scanned for embedded active challenges, `one-time-code` was
not reviewed, initial input value attributes did not always equal Chromium's
FormData values, and cookie headers lacked path-priority/stable replacement
ordering. It also claimed datalist descendants were not successful controls;
an isolated Chromium `FormData` observation included them, including a password
input, so that proposed filter was not applied. The other four findings failed
before repair (51 passed, 4 failed); the current 55 session cases now pass.
Probe challenge checks precede lesson-ID admission; OTP is review-only; input
defaults/sanitization follow the covered Chromium cases; cookies use longest
matching path first and stable creation order. Governor bytes stayed unchanged
and campus requests remained zero. The full native gate, fresh complete-source
review and actual authentication for this exact SHA remain pending; no password
has been submitted under the new field contract.

The next exact-source review (module SHA `0c2a08004e4071d8804448821f75a917c7fa27c5d07913706d7488657d1cf3a1`) found three additional defects: hidden-value line breaks were sanitized, CSS color functions accepted extra components, and the body-text veto omitted supported verification markers such as `校验码`. The attempted full native gate stopped at strict clippy (`question_mark`, exit 101) before running tests. Chromium FormData separately confirmed hidden values retain LF and malformed RGB/HSL/color-space functions default to black. The code now preserves hidden values, validates exact CSS component/alpha shape, tightens number/time value syntax and shares the full challenge-marker vocabulary with the response veto. All 56 session cases passed on source SHA `5738e8c6831831845ae5059fb50651668354e9678c12dfe98a42e36eec255550`. That exact source subsequently passed the full native gate (466 library, 19 CLI, 3 ignored workers; strict clippy, fmt, build, whole-manifest equality, stable source/governor and zero campus requests), but its fresh review found two more reachable mismatches: CSS function token whitespace/uppercase hue units, and split-node active text. Both are fixed. The current 57 session cases pass on module SHA `7cc8d3f0a5883dd12f83c10bae23214475ff28495c8d58f098edc79e67b920bd`, with stable source, unchanged governor bytes and zero campus requests. Its complete native gate, fresh complete-source approval and one deliberate governed authentication remain pending.

`buaa recordings session --offline` deliberately arms one authentication
attempt without network access. `--online` receives authorization, the
credential, the exact typed intent and an explicit selected-lesson
verification on protected stdin. The credential-bearing request is pinned
to the reviewed SSO service; redirect, challenge and application-response
admission remain subject to the same account-wide governor. A negative or
indeterminate result is not permission to rearm automatically.

An admitted classroom session is stored privately and referenced explicitly.
Positive selected-lesson application confirmation is not independent proof of
account identity, media rights or course completion. `recordings subtitles
--online` accepts the stored reference as `session_ref` instead of an
operator-pasted cookie. Exactly one of `cookie` or `session_ref` is required.
Stored version-3 sessions retain acquired cookie scope, declared identity
domain, Path and expiry and
filter each actual API URL; old flattened files require deliberate authentication.
The hardened source passed strict all-target clippy, an explicit locked
offline build, 432 library cases and 19 CLI cases with three worker entries
ignored. Native consumers matched the full 51/74 manifest, all 2,455 retained
supplied cues and all 3,389 raw-source cues. Complete retained media readback
also matched; these checks made no campus requests and left the production
governor unchanged. Fresh exact-head review and original-runtime online smoke
remain separate gates; earlier login receipts are not their approval.

The original UID1000 runtime subsequently built its own offline artifact and
executed help, schema and the entire 51/74 manifest successfully. The host
artifact's earlier libc incompatibility is not retried or hidden by copying it.
One governed session attempt then recorded only an initial SSO HTTP 200 and
stopped before password submission with `challenge_required`; no session was
stored. The sanitized receipt does not identify whether a response challenge
signal, CAPTCHA field, or form-control safety scan triggered the refusal. At
that head the local unreviewed-control sentinel shared the CAPTCHA
classification, so `challenge_required` did not prove an actual CAPTCHA.
The current source separates confirmed challenge from unreviewed-interaction
refusal; an unreviewed initial form stops before password submission, while
later responses do not claim whether a password was submitted. This does not
reveal which branch the original request took or authorize another login. The
diagnosed cooldown was zero, while
the challenge latch remained set; waiting alone does not clear that latch.
No automatic authentication retry or challenge bypass occurred.

The fresh review of the next exact head found that raw `captcha`/`challenge`
substrings in post-submit HTML could label inert hidden login-page containers
as an actual challenge. The source now derives that classification from
response challenge headers or an active enabled challenge control in the
reviewed form. A raw-body keyword still vetoes session admission, but cannot
itself label a challenge. Synthetic regressions cover the retained hidden
container and hidden/disabled challenge controls; a fresh full gate and review
are required for this exact change.

The independent reviews then found valid CSS priority whitespace and comments
could bypass the inline-hidden check and produce a challenge receipt. The
parser now strips CSS comments before declaration/property parsing and removes
priority tokens before testing hidden values. Synthetic contiguous, spaced,
comment-separated and comment-in-property `display`/`visibility` cases remain
fail-closed as unreviewed interactions, not confirmed challenges. Exact head
`e9dc437622be38fb2d6a8d9819667b52ee0711eb` passed the full offline gate,
original UID1000 build/smoke, and two exact-head GitHub Actions checks; a fresh
independent full-source review explicitly approved with no concrete P1/P2.
Copilot's review bot reported requester quota exhaustion, so that bot review
is not an approval. The current online session remains unverified: its earlier
challenge latch is still set and the sanitized receipt does not reveal the
original trigger. No repeat authentication or challenge bypass occurred.

Both initial exact-head GitHub offline checks exposed a remaining-time test
assertion that ignored elapsed milliseconds. The regression now checks the
absolute thirty-minute deadline and its retention after body failure, without
changing production pacing or cooldown. The corrected local gate passed
432 library and 19 CLI cases. Those earlier CI failures remain historical
failures; the later exact-head checks for e9dc437 succeeded.

Runtime admission also found two distinct governor entities: the migrated
original runtime retains a 60-second request interval, whereas prior host
observations used a later local five-second store. Those host receipts do not
establish original account-history continuity. Further campus operations must
use the existing original production runtime and honor both known sets of
barriers; neither history is copied, reset or silently merged.

## Observed classroom session, recording media and native subtitles

Earlier candidates completed a CAS/forwarding flow and stored platform
cookies. These receipts preceded independent findings in positive-session
admission, cookie scope, request pacing, body limits and response lifetime.
They remain historical observations, not a security or current-head approval.

The platform APIs declared a released replay and a recording asset. An earlier
candidate read a one-mebibyte prefix with HTTP 206 and acquired all
2,068,314,499 bytes of a `video/mp4` with a privately retained whole-file
digest. The recording host answered without the classroom cookie. The
local original is retained for offline readback; it need not be downloaded
again to repair transport or parser defects. Private lesson identifiers,
recording dates, source digests and operational paths stay outside Git.

One native subtitle track was read through the governed
fixed-origin endpoint with the stored session reference: 3389 cues in source
order, spanning 219 s to 8897 s, from a 595,620-byte original, revalidated
with HTTP 200 and an unchanged body digest. The platform serves that envelope
with an HTML content type, so the response body is now the admission
authority and the labelling drift is reported in the receipt; an HTML sign-in
page still fails the envelope admission and is refused without being
retained.

The native track has no resource identifier. Platform lesson metadata is an
association lead; date/duration agreement and caller-supplied cue facts do not
independently verify a native media binding. Nine sampled mpv cue windows
showed localized subtitle differences and four early gap samples did not.
VLC root captures were black; later window captures used unmatched frames and
remain inconclusive. Neither finite sampling nor process exit completes
all-cue, dual-player synchronization or realtime-live acceptance.

## Bounded local player delivery

The local replay command now launches installed mpv/VLC with explicit
authorization, descriptor-bound media/subtitles, initial seek, optional
headless output and bounded shutdown. Internet socket creation and io_uring
are denied in the Linux x86-64 player child; Unix display/audio IPC remains
available. Player configuration and external helper/script autoload are
disabled. This is not a general decoder/filesystem sandbox.

An actual guarded CLI run exercised both players with supplied SRT tracks,
initial seek and bound-triggered stop/reaping. A separate segments-to-SRT run
verified submission and cleanup. Independent mpv/X11 screenshots at one
paused source frame showed subtitle-only pixel differences; exact seek and
subsequent playback/audio-clock advancement were observed. These local
observations do not certify ASR accuracy, native media-track association,
physical speaker output, live playback or universal synchronization.

The earlier guarded player quality gate passed formatter, locked offline build, strict
all-target clippy, 389 library cases (two worker entries ignored), 19 CLI
cases, native manifest/subtitle/report consumers and 15 announcement schema
cases. Earlier failed flag, generated-file readback and export-bound fixture
receipts remain retained; they are not rewritten as successes. Private media,
text, paths and image evidence remain outside Git.

## CI account-lease lifetime correction

The native-evidence PR's push run failed with an account-lease contention
error; its separate pull-request run passed. The failed run is retained,
not retried into a success. Moving the sandbox probe from bare fork to an
exec-isolated worker passed its focused check but did not alone fix the
default-parallel suite: a later run still had 12 lease-related failures.

The governor now explicitly unlocks when its original owner releases the
RAII guard. A duplicated descriptor can otherwise keep flock alive after
the owner closes it, including during another thread's fork/exec window.
The guard records its acquiring PID so a fork child's destructor cannot
unlock a parent's active request. All acquisition paths retain the guard
through state processing and persistence. Pacing, latches, authentication
and durable unknown-outcome rules are unchanged.

A deterministic inherited-descriptor regression preserves the rejection
latch and full request gap after completion. The corrected locked offline
gate passed 25 focused governor cases, 390 library cases and 19 CLI cases
with default test parallelism; three subprocess worker entries were ignored
in the full suite. Formatter, strict all-target clippy, build, whole 49/74
manifest equality and all 2,455 native cues also passed. The initial local
parallel run exhausted its 2 GiB virtual-address limit; its failure remains
retained. The completed gate kept that limit and default parallelism while
bounding glibc arenas with `MALLOC_ARENA_MAX=2`.

## Original-runtime governor continuity

After explicit operator authorization, the existing BUAA container's
original history was migrated with the local-only exact boot-review plan
and commit, not deleted or replaced by the newer host-only state. Independent
readback matched the complete retained old-byte digest and unchanged
permanent lock inode/permissions. The original 60-second request policy and
15-minute background policy remain; full residual waits of 60,001 and
900,000 ms were newly reserved, and the old armed authentication permission
was disarmed. No campus request was sent by this operation.

Further campus reads must use that original shared namespace, not the
later host-only five-second history. This resolves the original-runtime
boot-continuity blocker, not service adapters, media rights, authentication
or live-stream contracts.

## Retained native subtitle source revalidation

The original private evidence survives in the existing BUAA seat's persistent
home mount even though its container-local path is absent from the host home.
Only the retained original, import input and independent pre-implementation
oracle were copied to a new private directory; their complete hashes match
the retained copies. No seat was started or restored, and no production
governor, credential or campus service was accessed for this verification.

The current compiled CLI imported all 2,455 cues from the 636,471-byte native
original under the foreground heavy-work guardian. Every cue field, exact
selection, original length/hash and independently recomputed emitted-segment
digest matched. The native empty resource identity stays explicitly missing;
media association, fresh authentication, complete history and live delivery
are not proved. Private inputs and full output remain outside Git.

A later full-window VLC/X11 observation showed subtitle glyphs and advancing
playback time. Earlier captures clipped the native window's subtitle region;
the paused toggle comparison remained unchanged and is inconclusive. This
adds a bounded rendering observation, not whole-track synchronization proof.

Read-only Life tool inspection located selected-course replay capture and MP4
acquisition, with ASR as a separate downstream source of local SRT files.
The finite-HLS collector rejects ongoing playlists. Neither that replay path
nor empty translation/socket metadata establishes a native subtitle or live
service contract; no private implementation was copied or executed here.

## 2026-10-21: Governed public online verification

A filesystem check found no production governor directory in the effective
UID's passwd home at observation time. Local absence does not prove that
history never existed or establish continuity with the earlier container
runtime. The review command refuses to create missing history; normal open
subsequently created a private 0700 directory with a 0600 lock and state file.
No existing local governor files were deleted. The earlier claim that there
could have been no historical waits or unknown outcomes was not established.

Credential-free public reads then succeeded through the shared governor and the
owner's egress proxy:

- The official directory returned HTTP 200, 41857 bytes and 50 entries, and the
  offline replay of the same source returned a cache hit with an identical
  digest.
- The computer college root, its declared 公告公示 board, the 10-row college
  listing and the board-declared article all returned HTTP 200; the article
  reported 2026-10-19 with 2 body paragraphs and `full_text`.
- The university news centre 通知公告 listing returned 5 rows.
- Current college root surfaces were observed for math, h3i, sse, mse, wrj and
  yqgdxy.
- Two CDX lookups returned captures, including 100 captures for the computer
  college root; a governed capture of both targets was refused because the
  archived replay redirects and this adapter does not follow redirects.
- The SPOC public root and entry surfaces plus the currently declared
  application bundle were read. The root digest still matches the 2026-09-28
  observation, while the entry digest and the application bundle fingerprint
  changed, so the earlier bundle reference is stale.
- The campus gateway usage read now succeeds and reports the session online.
  The two earlier edge failures stay on record. No credential was sent, no
  login was attempted and no account mutation was performed.

The observed governor enforced cooldown/interval denials. The CLI created
private response caches. Account network identifiers and response digests
are excluded from the current public manifest; earlier Git revisions may
retain the previously published fields. This correction is not historical
erasure. No account login or campus write was performed.

The remaining gaps are unchanged: ME and EE still fail TLS validation, Sa stays
root-only, Rse still has no source-declared board, the SPOC authenticated
course and material contract is still unverified, archive capture of a
redirecting replay stays refused, and the pinned template fetch reports a
conflicting cached artifact. Live playback, whole native-track/media binding
and live subtitle updates remain unverified.
Bounded local replay/export/delivery is implemented as described above; it is
not a complete online media service. The ihome and department-material items
remain reference catalogs without implemented source adapters, not working
services. Further campus observations still require reviewed continuity with
the original permanent governor; prior successful requests do not establish it.

## 2026-10-21: Source-admission repair round, offline only

Sixteen independently reported source-admission, transport-safety and
owned-scope findings were reduced to twenty-two offline regressions on the
integrated candidate descended from `b37f3fbc80f25c7b79bcb104d7400c33ed3d65c9`.
Every regression failed before the repair and passes after it; no assertion
was weakened to fit the previous behaviour, and the failing baseline remains
retained separately.

The repaired contracts are narrow and source-bound. A safe admitted board or
article whose selector no longer matches keeps its original bytes and reports
a typed fallback, while the selection error stays nested until the response
has been retained. An unsafe response, including authentication, password,
CSRF, CAPTCHA and challenge markup or headers, remains an outer refusal and
never enters the public cache or the fallback path. Challenge and captcha
headers are observed before retained metadata is filtered, and a rejected
classroom session stays latched even when a later encoding or MIME error
occurs. Article bodies and embedded documents are bound to their owning
container, so inert templates, comments, strings and unrelated sibling
containers can neither authorize a document nor supply text. Notice rows stay
inside their declared notice-list scope, listed links resolve against the
admitted listing URL, ambiguous nested category tables are refused, and
omitted table content is reported as partial text.

The unified gate passed with one foreground shared heavy-work lease, the
owning worktree's target, UID1000, one compiler job, a 2-GiB memory limit
(3 GiB including swap), a read-only container root and no network. The
formatter check, locked offline build and strict all-target clippy passed;
the complete suite passed 372 library and 19 CLI cases, with the same two
ignored subprocess worker entry points. The actual CLI manifest equals the
complete 49-capability manifest, the synthetic all-cue subtitle import
preserves content, order, translation and exact millisecond timing with an
independently recomputed digest, the report consumer keeps stdin-only bodies,
an explicit repository host, spoof refusal and an unknown outcome without
retry, and all 15 published announcement schema cases pass. The source input
set digest for that run was
`413ef97880a7ab9aecd1a95828f9bfe14c393f494e5310825ae3bd8bf7f0a0d3`.

These are synthetic and offline results, not current campus observations. No
campus request, authentication, mutation, credential, production governor or
private cache was used. ME, EE and Sa transport blockers and the missing Rse
notice-board contract are unchanged, current online acceptance still requires
the original governor's deliberate reviewed boot-history admission, and the
pre-existing failing trusted check on the earlier stack head remains a
separate open gate.

## 2026-10-21: Unsafe nested listing retention corrected

An independent source-only review of the integrated candidate found one P1
admission defect: the nested `unsupported` result used for safe selector
drift was returned after a structurally valid listing parse without rechecking
security markup. A password/CSRF response could therefore be persisted before
the caller observed the unsupported article. The review did not access live
sources, private caches or credentials.

The fix adds one shared `refuse_unsafe_listing` guard and calls it from the
seven affected article-discovery consumers (Yqgdxy, ASE, WRJ, BME, FLD, HSS
and Math). Safe admitted drift still retains original bytes for offline repair;
authentication, password, CSRF, CAPTCHA, challenge and active-base responses
now fail outward before cache persistence. A real loopback regression uses a
selector-valid Yqgdxy listing containing password/CSRF markup and verifies an
`unavailable` outer error, no cached listing and one request.

The focused source-admission set passed 23/23 cases. The unified source gate
passed formatter, locked offline build, strict all-target clippy, 373 library
cases (two ignored subprocess workers) and 19 CLI cases. The actual CLI
manifest and subtitle/report consumers passed as before. A fresh schema
recovery, bound to the same source digest
`3f481183a009325efa6fffa69a036ef5b0168aa323fec372a9c792746a219683`, passed
all 15 published schema cases. All verification used one global heavy-work
lease and no network or campus request.

This remains offline evidence, not current campus or authenticated-service
acceptance. Online governor boot-history admission, ME/EE/Sa/Rse blockers,
playback and player-facing subtitle delivery remain separate gates.

## 2026-10-21: Target-present unsafe listing bypass corrected

A second independent security review of head `73583fe916dac4f7be445531c9f10f5dd3f087a8`
found that the first P1 guard was still inside the target-not-declared branch.
An unsafe selector-valid listing that declared the requested target skipped the
guard and could be persisted. This was a source-only finding; no live or
private response was accessed.

The guard now runs immediately after each of the seven listing parsers and
before target membership is tested. Both target-absent and target-present
password/CSRF listings fail outward before cache persistence, while safe
admitted drift retains its original nested result. The loopback regression now
exercises both target shapes and passes 23/23 focused cases.

The P2 unified offline gate passed formatter, locked build, strict all-target
clippy, 373 library cases (two ignored subprocess workers), 19 CLI cases and
15 schema cases. Its source input digest is
`39e7c84ba93fa81a99be164a292385c5164adfa507225714cc1363648213a0b3`.
No network, campus request, authentication, mutation, credential, production
governor or private cache was used. Final exact-head independent approval
remains a merge gate.

## 2026-10-21: Legacy article-discovery guards added

A delayed aggregated source review identified the same target-present unsafe
listing bypass in the older Aviation, IAI, IC, IIIF, Shenyuan, H3i and Beijing
article consumers. Their parsed listing rows could declare the requested
article and return retrieval without the shared safety guard.

The follow-up adds `refuse_unsafe_listing` immediately after admitted HTML
parsing and before membership testing in all seven consumers. Safe behavior is
unchanged; unsafe target-present password/CSRF responses fail before cache
persistence. A real loopback Aviation regression covers that target-present
case, verifies `unavailable`, an offline cache miss and exactly one request.

The follow-up focused set passes 23/23 cases. Its unified offline gate passes
formatter, locked build, strict all-target clippy, 374 library cases (two
ignored subprocess workers), 19 CLI cases and 15 schema cases. The source
input digest is
`69185a30be142411fc3af4c664b73dea0a90ce268a3ce23772d87159c4f1923a`.
No campus request, authentication, mutation, credential, production governor
or private cache was used. This is a follow-up source-safety proof, not online
campus or rights-cleared media acceptance.

## 2026-10-20: Unified native offline gate, not online acceptance

The integrated candidate descended from `74d463227d07cc822b0d64b56b5fa99874fad583`,
including formatter output, the SSE correction and the canonical announcement
schema cutover, passed locked offline build, strict all-target clippy and
formatter check. The complete suite passed 350 library and 19 CLI cases;
the two ignored library entries are subprocess worker entry points, not
newly waived checks. Verification used one foreground shared heavy-work lease,
the owning worktree's target, UID1000, one compiler job, a 2-GiB memory limit
(3 GiB including swap), a read-only container root and no network.

The actual compiled CLI's capabilities equal the complete 49-capability,
74-catalog manifest. Native synthetic consumers preserve every supplied cue,
text, translation, source order and original/derived digest; fake-gh consumers
verify stdin-only issue bodies, an explicit GitHub repository host, spoof
refusal and reconciliation without retry. No real Issue was created.

SSE no longer prints source paragraphs to stderr. Its attachment regression
requires the owned `Source.pdf` hint and excludes the link outside `art-main`.
The first report fixture failures were traced to Docker's default `noexec`
tmpfs: the default-mount probe returned EACCES, while an explicit executable
tmpfs succeeded. No report result was weakened to accommodate that executor.
Separate focused SSE/report runs passed 3/5 cases and overlap the full suite.

Sixty-two obsolete post-construction schema mutations were removed. A native
consumer of the old binary failed six checks; the rebuilt CLI passes all 15,
including IAI discovery, all 29 listing colleges, HSS HTTPS-only articles,
Transportation's reviewed namespace, BME's exact query shape and retained MSE
table types. The validated Rust/Cargo/manifest input-set digest before this
evidence update is `ec87e4ffc53e8e6a83a334213021934b0ed656269ae1c4b74fed421c2274bf30`.
Original failed receipts remain retained separately.

These are synthetic/offline results, not current college-source observations,
authenticated service or player-delivery proof. Production governor history,
credentials and private response caches were not mounted; no campus request,
authentication or mutation occurred. Current online work still requires the
original governor's deliberate reviewed boot-history admission. ME/EE/Sa TLS
and Rse's missing reviewed notice-board contract remain explicit blockers.
Exact-head independent review, publication and online acceptance remain gates.

## 2026-10-20: Public fallback and HSS retention correction

The shared raw-HTML fallback boundary now admits only status-200, bounded,
UTF-8 `text/html` responses without active `<base>` semantics or structural
authentication/password, CSRF, CAPTCHA and challenge attributes. BME, FLD and
HSS downstream selector fallbacks use that admission while source-admission and
article-binding failures remain outside raw serialization. HSS `showVsbpdfIframe` and preview declarations are parsed
without execution; inactive/commented/string preview text cannot authorize an
embedded document, preview paths remain derived metadata, and conflicting
original declarations fail. HSS later pages require an explicit source ordinal
and link label rather than a filename-derived ordinal; missing/conflicting
ordinal errors remain nested until `ArchiveClient::get` has retained the
admitted listing response. The unified native offline gate above has passed;
production cache-only source comparison and current online verification
remain pending. No all-college completion or current-source claim is made.
## 2026-10-20: Native subtitle capability cutover

The omitted native subtitle capabilities were restored from the authoritative
source worktree into the integrated transport without copying private source
receipts or credentials. `recordings-native-subtitles` is represented as
implemented-offline: supplied input is permission-gated, bound to the exact
original bytes, selects one `(sub_id, resource_guid)` pair, validates every
cue, preserves source order/text/translation and hashes the emitted segment
value. `recordings-native-subtitles-online` is represented as
implemented-offline for its fixed-source existing-session adapter: URL/cookie
scope, fresh JSON/application admission, immutable raw-body provenance,
session-scoped cache and the permanent shared governor are wired. Six import
and five transport regressions passed in the unified suite; the actual CLI's
synthetic all-cue/digest consumer passed. Existing-session online validation
and comparison to complete authorized retained originals remain parent gates.

The restored regressions and schemas are synthetic/offline source consumers;
this entry does not claim online verification, accepted authenticated target
bytes, media rights, catalog writes or publication. Replay and live playback
remain pending. Player launch, seek, controlled stop/exit, actual audio/video,
player-facing subtitle delivery, rendered cues, synchronization and live
subtitle updates are still unimplemented; JSON import/schema discovery does
not satisfy those acceptance items.

## 2026-10-18: Dept3 current board contract

Read-only public reconnaissance through the shared proxy found that the current HTTPS root `https://dept3.buaa.edu.cn/` declares the exact board `https://dept3.buaa.edu.cn/xwdt/gggs/tzgg.htm` (labels 公告公示/通知公告). The old `/xwzx/xygg.htm` route and category1302 contract are no longer admitted. The selected HTTPS root remains a deliberate observation of the official directory's exact literal/resolved HTTP identity `http://dept3.buaa.edu.cn/`; it is not an upgrade, alias or academic school-code assertion.

The board is one active `nymain/notice-list` view with direct `ul > li > a` rows, direct `span` dotted dates (`YYYY.MM.DD`), direct `h3` source headings and direct `p` excerpts. Its pagination declares only ordinal1, so the adapter accepts `category=tzgg`, page1 only and never infers later pages. The five current source rows link to two source-declared article namespaces, `/info/1093/<id>.htm` and `/info/1014/<id>.htm`; external references remain retained listing links and are never fetched.

Declared articles use one `form > div.art-main`, direct `div.art-tit.cont-tit > h3` heading, direct `span.date` Chinese publication metadata and one scoped `art-body-box/art-body/#vsb_content/v_news_content` body. Shared bounded paragraph/table extraction preserves source order; images and attachment contents remain unfetched and degraded output stays `partial_text` when applicable. History admissions, schema, help, dispatch and network path allowlists use the same exact board/article declarations. The earlier Dept3 section below records the superseded route and is retained as historical evidence only.

## Directory-bound Chemistry college news

The Chemistry adapter binds the non-hidden official-directory member `化学学院` at the exact listed/resolved HTTP root `http://sce.buaa.edu.cn/` and deliberately observes the HTTPS root separately. The retained root declares the active `xwzx/xyxw.htm` 学院新闻 board; the adapter does not infer the adjacent notification, research or student routes. Listing rows are the source-ordered direct rows under one active `.fy-list > ul`, with direct `YYYY-MM-DD` date spans and article anchors. Later pages are selected only when the retained pager advertises the requested board path; no ordinal traversal or guessed URL is used.

Article admission is restricted to HTTPS `sce.buaa.edu.cn/info/1013/<digits>.htm` URLs declared by the selected board. The parser binds one `.c-content` title, one `.other-s` 发布日期 marker and one scoped `#vsb_content .v_news_content` body. Active paragraphs are retained with shared budgets; image-bearing text is `partial_text`, while image-only content remains unavailable. Foreign, credential-bearing, query, fragment and unreviewed paths fail before transport. Root/list/article/surface reads use the shared governor/cache profile; no attachment or image bytes are fetched.

## Directory-bound Software-college notices

The official directory records the visible `软件学院` member as the exact
literal/resolved `http://soft.buaa.edu.cn/`. The selected HTTPS observation
retains that HTTP identity and is not a protocol alias. The HTTPS homepage
declares `/xwdt/gggs.htm`; that section declares the selected
`/xwdt/gggs/tzgg.htm` 通知公告 board. The adapter binds both declarations
before reading the source-ordered `nymain/notice-list` rows, and only accepts
source-advertised `/xwdt/gggs/tzgg/<digits>.htm` pages plus declared
`/info/1095/<digits>.htm` originals.

`college=soft` with `category=tzgg` supports inclusive date/title filters,
`college-source soft root|notices`, and selected source-page article reads.
Article extraction uses the unique `art-main`/`art-tit`/`v_news_content` scope;
source-declared JSP files are unfetched hints, while image and table content
remains explicit `partial_text`. Credentials, queries, fragments, custom
ports, foreign hosts, guessed routes and automatic page traversal are
rejected. The live source currently exposes one page; no complete history or
all-college coverage is claimed.
## Directory-bound Physics college notices

The retained official directory member25 is 物理学院 with exact literal/resolved `http://physics.buaa.edu.cn/`; the selected `https://physics.buaa.edu.cn/` observation is kept separate and is not an HTTP upgrade or alias. Credential-free public reconnaissance through the approved proxy observed a 24,601-byte HTTPS root, which actively declares `index/tzgg.htm` as 通知公告. The retained board is 14,566 bytes, advertises 26 total source rows and an ordinal link `index/tzgg/1.htm`; selected article paths are `/info/1252/<digits>.htm`.

The adapter binds the retained directory identity, root-declared board, source-ordered `ul.news-ul > li` rows with direct `a`/`span` ISO dates, advertised `div.pb_sys_common span.p_no a[href]` pagination, and original `div.article-tt`, `div.article-sm` (`发布时间：YYYY-MM-DD`) and nested `div.article-txt div.v_news_content` content. URL admission is HTTPS-only, credential/query/fragment/port-free and limited to robots, root, board, advertised board pages and category1252 originals. No guessed route, automatic traversal, attachment download or campus write is enabled. Public reconnaissance hashes: root `31ef8ad1e908888b3d15460ff6f4c5f4c3805d58ba3d619a2bbc3e21d12f0872`, board `90fffa5a28bb734803bc15ab38c68c5fff407192a9c7ffd608228214a3f053a8`, selected article `be17adc3ad361827aac0e76ef057937147295df7635c670056012c70734ca8d7`; these are source observations, not native governor/cache proof.

`announcements college-source physics [root|notices]`, `announcements list` with `college=physics`/`category=tzgg`, and declared-board `announcements article` are wired through the existing shared governor/cache and directory attribution. Synthetic parser tests cover source order/date filters, inert/foreign pagination refusal, original publication/body scope, ambiguous body refusal and URL boundaries. Full offline/native verification and exact-head publication remain parent-agent gates.

## Space and Earth sciences announcements

The exact official-directory member26 is 空间与地球科学学院 with literal/resolved `http://sse.buaa.edu.cn/`; the source order is not a school code. The adapter deliberately selects `https://sse.buaa.edu.cn/` separately and preserves the HTTP directory identity rather than asserting protocol equivalence. Public root discovery returned HTML 200 (54,269 bytes) and declares `xwdt/gsgg/tzgg.htm` under 新闻动态 → 公告公示 → 通知公告. The board returned HTML 200 (28,122 bytes), with one current source-ordered `nymain/notice-list` view, direct `li > a > span` `YYYY.MM.DD` dates, `h3` headings, `p` excerpts and no advertised later-page anchor. The selected first article namespace is `/info/1078/<digits>.htm`; its original layout is one direct `art-main`, `art-tit > h3`, `art-tit > p > span.date` (`日期：YYYY年MM月DD日`) and `art-body-box > art-body > #vsb_content > .v_news_content` body.

`announcements college-source sse root|notices`, `list` with `college=sse`/`category=tzgg`, and declared `article` now use the same cache-first client, permanent process-shared governor, directory binding, source-declared pagination and selected-only refresh as the other directory-bound college adapters. The network profile admits only HTTPS root/robots, the declared board, advertised board pages and canonical `/info/1078/` articles; credentials, queries, fragments, custom ports, foreign hosts, undeclared categories and guessed routes are rejected before transport. Article output keeps source paragraphs and publication metadata separate, reports active images/tables/unfetched JSP attachments as partial content, and never downloads attachments or reconstructs image text.

The only mandatory robots response observed through the approved proxy was HTTP 404 (1,693 bytes, standard shared robots-missing body); root, board and one declared article were separately observed as HTTP 200. Response originals remain private and are not fixtures. Missing later-page declarations, other board categories, complete history, attachments/OCR, authenticated services and campus writes remain out of scope. Offline synthetic coverage in `src/announcements/sse.rs` defends row/date/order preservation, direct article scope/partial-content boundaries and canonical URL/path admission; parent-owned locked cargo/build/clippy/formatter gates remain required.

## Directory-bound SEM economics and management notices

The SEM adapter binds the authoritative directory member `经济管理学院` with its exact listed/resolved `http://sem.buaa.edu.cn/` identity, then deliberately observes `https://sem.buaa.edu.cn/` separately; this is not a silent HTTP upgrade or protocol-equivalence claim. Public read-only reconnaissance found the root-declared notice board `https://sem.buaa.edu.cn/xwdt/tzgg.htm` (`通知公告`). The board uses one active `ul.d-newsU5` list, direct `a.inner` rows with `div.text > h4.tit` headings, and split `div.date > div.t1` month-day plus `div.t2` slash-year dates. Its first page advertises `tzgg/<ordinal>.htm` pages and includes both own-site `/info/1024/<id>.htm` notices and external WeChat links; external destinations remain metadata only.

`college=sem` is implemented for root/notices surface snapshots, `category=tzgg` listings with inclusive date/title filters and source-advertised page selection, and canonical `/info/1024/` articles declared by the selected listing. Article extraction binds one `d-detail1`/news-content form, direct `h1.tit`/publication metadata and one `vsb_content/v_news_content` body. Embedded viewers, images, tables and source-declared sibling JSP files remain unfetched and are reported as `partial_text` or `attachment_only`; no prose is invented from scripts or PDF previews. Query, credential, foreign-host, wrong-category, unadvertised and undeclared URLs fail before transport. Synthetic listing/date, duplicate-board, article-body/attachment, attachment-only-viewer and URL-admission cases are included in the adapter module. No history completion, attachment download, campus mutation or all-college coverage is claimed; native build/test evidence remains a parent integration gate.

## Directory-bound Fld foreign-languages notices

The `fld` adapter binds the visible official-directory member `外国语学院` whose literal and resolved identity is `http://fld.buaa.edu.cn/`. It deliberately observes `https://fld.buaa.edu.cn/` separately and requires that root to declare `https://fld.buaa.edu.cn/xwzx/zxtz.htm` before listing or article reads. The selected board is `college=fld`, `category=zxtz`; source rows use the complete `title` attribute, direct `YYYY-MM-DD` row dates and canonical `/info/1011/<id>.htm` declarations. Later pages are selected only from active `div.fanyxh a[href]` ordinal links, never guessed.

The article contract is the reviewed `div.ljkm23` layout: direct `mch3` title, `mch3sh` `发布时间：YYYY-MM-DD` metadata and one `#vsb_content > .v_news_content` body. Source-declared `showVsbpdfIframe` originals and `vsb_pdf_image_data` previews remain unfetched `embedded_document` metadata; no PDF/image download or OCR is implied. Listing/article/surface selector drift returns governed response bytes as base64 `raw_html` with `content_type`, byte length and `fallback_reason`; foreign, query, credential, custom-port and fragment routes are rejected before transport.

Focused synthetic parser coverage is included in `src/announcements/fld.rs` for source title/date/link preservation, PDF-only embedded-document handling and foreign/query URL rejection. Native build, online governed source capture, cache-only replay, capability evidence and independent review remain owner-side gates; no deployment, merge or campus mutation is claimed here.

## Mechanical Engineering and Automation source boundary

The official directory member is preserved exactly as listed/resolved `http://www.me.buaa.edu.cn/`, under the name 机械工程及自动化学院. Read-only public reconnaissance through the approved proxy found the root-declared `xyxw.htm` 学院新闻 board (article namespace `/info/1126/`, source-advertised 56-page pager) and `xszx.htm` 学术资讯 board (article namespace `/info/1128/`, source-advertised 18-page pager). The observed selectors are source-specific: `div.news_l > div.news_l_con > ul > li` rows with direct `a`/`p` title/date fields for 学院新闻, `div.noticer > dl` with `dt`/`dd` anchors for 学术资讯, and article `div.news_r > div.news_r_tit`, `p.news_r_tit2`, `div#vsb_content > div.v_news_content` fields. Pagination and article links are source declarations only; no URL is inferred.

The HTTPS candidate `https://www.me.buaa.edu.cn/` is not currently admitted: TLS validation reports a certificate subject-name mismatch for `www.me.buaa.edu.cn`; a separate HTTPS probe of canonical `me.buaa.edu.cn` ended unexpectedly during TLS. The adapter therefore remains **surface-only/blocked**. `college-source me root|notices` retains the literal HTTP directory attribution and reports a structured `tls_transport_blocked` fallback; `college=me` list/article inputs refuse before transport. Plain HTTP requests, TLS verification bypasses, foreign/query/credential URLs and unverified source bytes are not used. A valid HTTPS source observation is required before listing/article extraction can be enabled.

## Directory-bound Wrj无人系统研究院 notices

Owned `work/wrj-adapter` adds the directory-bound `wrj` capability for 北京航空航天大学无人系统研究院. The retained official-directory snapshot identifies visible member10 under 航空航天学科群 with exact literal `http://wrj.buaa.edu.cn` and resolved `http://wrj.buaa.edu.cn/`; the source order is not an academic-unit code. The selected HTTPS root `https://wrj.buaa.edu.cn/` is a deliberate separate observation, not an HTTP upgrade, alias or protocol-equivalence assertion.

Proxy reconnaissance selected the root-declared `https://wrj.buaa.edu.cn/xwgg/tzgg.htm` 通知公告 board. Its current source layout is one scoped `div.main > div.w90 > div.main-right > div.content > div.txt-list > ul` view, with direct `li > a.line1` title links and `li > span` `YYYY-MM-DD` dates; its pagination control is the scoped `div.pb_sys_common span.p_no` declaration. The selected board declares category-1008 article `/info/1008/3067.htm`. Its article contract is one active `_newscontent_fromname` form, direct `h3.title`, one `art-itro` `发布时间：YYYY-MM-DD` span, and one scoped `article > [id^=vsb_content_] > .v_news_content` body. Active JSP attachment links remain unfetched hints; image/table/attachment content is reported as `partial_text`, not reconstructed.

The adapter preserves source order, inclusive date/title filtering, source-advertised pagination only, exact directory identity, root-declared board binding, selected-only article reads and the shared governor/cache. Foreign, query-bearing, credential-bearing, noncanonical or undeclared URLs fail before transport. Raw public reconnaissance originals are not committed; governed native/cache proof and exact-head integration remain separate gates.

## Directory-bound Yqgdxy instrument-science notices

The retained official directory identifies visible 仪器科学与光电工程学院 with literal and resolved `http://yqgdxy.buaa.edu.cn/`. The adapter preserves that HTTP identity while selecting the HTTPS root separately; it follows only the root-declared `/tzgg.htm` notice board. The board uses one `div.nymain > div.ny-right > div.text-list > ul` view with direct row anchors and ISO-date spans. Later pages are selected only through the unique `div.pagination span.p_no` ordinal declaration; no filename arithmetic or automatic traversal is used.

`announcements list` accepts `{"college":"yqgdxy","category":"tzgg"}` and preserves source order, literal/resolved links, and unknown dates. `announcements article` accepts only HTTPS same-host `/info/1053/<digits>.htm` URLs declared by the selected board page. The article parser requires one owned `nymain/art-main` form, direct `art-tit/h3`, a unique leaf `日期：YYYY-MM-DD` span, and one scoped `art-body/v_news_content`; body links are hints only and no linked bytes are fetched. `college-source yqgdxy root|notices` exposes bounded source metadata with graceful retrieval facts.

Synthetic coverage exercises inert-row exclusion, source-order and ambiguous-date handling, owned article title/date/body extraction, allowlisted path boundaries, foreign/query-bearing URL rejection, and deliberate HTTP-versus-HTTPS identity separation. This branch contains implementation/docs only; no campus write, authentication, guessed route, source fallback, or acceptance-manifest mutation is claimed.

## Directory-bound ASE aviation-science notices

The official directory currently exposes visible 航空科学与工程学院 with the exact literal/resolved `http://www.ase.buaa.edu.cn/` member. Its root declares `https://ase.buaa.edu.cn/`-equivalent navigation only through the deliberate canonical HTTPS observation used by this adapter; the directory HTTP identity is retained in attribution and is not upgraded or aliased. Public reconnaissance observed the root-declared `/zhxw/tzgg.htm` notice board, ten source-ordered `div.txtList` rows, split `MM-DD`/year dates, advertised `/zhxw/tzgg/<ordinal>.htm` pages and `/info/1052/` or `/info/1285/` article links. The canonical article uses `div.arc-tit > h1`, one `发布时间：YYYY-MM-DD` header span and one `#vsb_content_2 > div.v_news_content` body.

The implementation adds `college=ase`, category `tzgg`, root/notices surfaces, source-advertised pagination and selected board-declared articles. URL admission is HTTPS-only on `ase.buaa.edu.cn`, with no query, credentials, custom port, fragment or unadvertised path; the shared production governor/cache profile remains the only transport path. Synthetic listing/article fixtures preserve source order, split dates, scoped body text and explicit image/table `partial_text` boundaries. No locked build, native CLI gate, cache oracle or formal online acceptance is claimed in this worktree; those checks remain parent integration work. No attachments, images, tables, OCR, complete history or campus writes are implied.

## Astronautics college source frontier

The retained official-directory member is visible 宇航学院, with exact literal/resolved `http://www.sa.buaa.edu.cn/`; its ordinal is source order, not a school identifier. Public read-only reconnaissance through the approved proxy found the HTTP root and the root-declared notice/news paths `index/xytz.htm`, `index/xyxw.htm` and `index/cggs.htm`. Their list layout is a distinct direct `con_list`/`li` contract with direct `a` and date `span` nodes; notice articles use `/info/1051/<id>.htm`. These observations are discovery notes, not admitted adapter originals.

The adapter preserves the directory HTTP identity and selects `https://www.sa.buaa.edu.cn/` only as a deliberately separate HTTPS observation. The selected HTTPS request is allowlisted to `/robots.txt` and `/` only; HTTPS validation through the approved proxy failed because the server certificate did not match `www.sa.buaa.edu.cn`, so no source bytes were admitted. The HTTP-only observations cannot be used as an HTTP fallback, TLS bypass, host alias or protocol-equivalence claim. `college-source sa root` is therefore surface-only; no Sa list/article route is advertised, and notice/original verification remains blocked on a usable verified HTTPS response or reviewed source contract. No campus mutation, authentication, route guessing or attachment retrieval.

## Directory-bound HSS Humanities and Social Sciences notices

The official directory's visible member 人文社会科学学院 (source order30) retains the exact literal/resolved `http://www.hss.buaa.edu.cn/` as directory metadata. Transport is HTTPS-only: the adapter selects `https://www.hss.buaa.edu.cn/` as a separate candidate and never uses the literal HTTP identity for egress. A bounded public read through the approved proxy observed the root-declared `xwzx1/tzgg.htm` 通知公告 board. Its source view is `div.n_right > ul.list > li`, with one direct `a` whose child `span` carries an ISO date; the board advertises display page2 as `xwzx1/tzgg/1.htm` through its legacy 下页/尾页 links. Selected originals are declared as `/info/1103/<digits>.htm`. The first retained page has20 rows and the advertised second page has one row; no later page is inferred. A usable validated HTTPS response is required before listing/article bytes are admitted.

The adapter preserves source order and date/title separation, rejects foreign/query/credential/noncanonical URLs before transport, and binds the board through the retained root declaration. The historical source observation described one `div.n_con`/`form[name=_newscontent_fromname]`/`div.contain_con`, direct `h2`, centered `发布日期：YYYY-MM-DD` caption and one `#vsb_content > .v_news_content` body. That HTTP observation is metadata only; the adapter admits bytes only from the separate HTTPS candidate, so no current original/document bytes are asserted until HTTPS validation succeeds. No plaintext HTTP egress, OCR, attachment download, complete history or campus write is claimed. Offline/native verification and acceptance evidence remain with the parent integration.

## Directory-bound BME information announcements

The retained official-directory member35 is 生物与医学工程学院 under 医工交叉学科群, with exact literal/resolved `http://bme.buaa.edu.cn/`. The selected HTTPS observation is deliberately separate (`https://bme.buaa.edu.cn/`), not an alias or silent protocol upgrade. The HTTPS root declares `newsList.aspx?catID=13` as its 信息公告 portal; the portal's active `table#DataList1` contains source category cells (`div.posTit`) and `ul > li` rows with bracketed ISO dates, full `a[title]` headings, visible anchor excerpts and declared `newsInfo.aspx?catID=13&subcatID=<digits>&curID=<digits>` article URLs.

The adapter preserves portal source order and title/excerpt distinction, accepts only the exact BME host and query shapes above, and scopes article extraction to one active `div.newsInfo`, direct `div.newsInfoTit > h3`, and its direct body. Paragraphs and bounded flat table captions/rows/cells are retained; image/document contents remain unfetched and produce `partial_text`. The portal's later page controls are ASP.NET `__doPostBack` declarations rather than independent GET URLs, so only the retained page 1 is supported; no postback, guessed page, category route, attachment, history, all-college crawl or campus write is claimed. Synthetic listing, URL-boundary and article/table tests are included; native build/test proof and external publication remain separate gates.

## Directory-bound YGY medical science and engineering notices

Public read-only reconnaissance through the shared proxy confirmed `https://ygy.buaa.edu.cn/` (HTTP 200), its active root-declared `https://ygy.buaa.edu.cn/tzgg/yggg.htm` 医工公告 board, three source-advertised board pages (`yggg.htm`, `yggg/2.htm`, `yggg/1.htm`), and canonical article links under `/info/1004/`. The captured root directory snapshot binds the visible member `医学科学与工程学院` to literal `http://ygy.buaa.edu.cn` and resolved `http://ygy.buaa.edu.cn/`; the selected HTTPS source is retained as a deliberate separate observation, not a protocol upgrade or alias. `ul.list1 > li` rows use `div.li-l > p.p1/p2` month/day values without a year, so the adapter preserves `date: null` rather than inferring dates. Article selectors are one active `div.content`, direct `h1` and `div.time`, and one `div.content-detail > div.v_news_content`; source-declared JSP attachment links, images and tables remain unfetched and are reported as partial content.

The implementation is local and unclaimed on `work/ygy-announcements-20261018`; no issue/PR, merge, deployment, campus mutation or governed native acceptance proof is claimed here. Full online/cache proof remains owner-controlled and must use the production governor and private originals; source history, all-college traversal and attachment retrieval remain out of scope.

## Directory-bound CST 网络空间安全学院 notices

The reviewed public source is `https://cst.buaa.edu.cn/`, selected separately from the official-directory member's exact literal `http://cst.buaa.edu.cn` (resolved directory root `http://cst.buaa.edu.cn/`). The root actively declares `index/tzgg.htm` as 通知公告. The adapter therefore binds `college=cst`, `category=tzgg`, and exposes only the root and that declared board; no guessed index, search, dynamic, or attachment route is admitted.

Public read-only reconnaissance through the shared proxy observed robots `404` (1693 bytes, SHA-256 `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407`), HTTPS root `200` (38235 bytes, SHA-256 `1d03ee24029caf2a6191ea9970fffc5f35f841d9d23f35d47bbb1225fa84ebe3`), declared board `200` (27454 bytes, SHA-256 `adf3d6f199ba34f5a13005442a1c8e4bbb320f4292e87296ae662efd43462a2e`) and one board-declared category-1102 article `https://cst.buaa.edu.cn/info/1102/5379.htm` `200` (32419 bytes, SHA-256 `c5af4743ea99cb457deb7a167d3cd65c96f905bcb4bb554fd5911ae36ab49027`). These retained observations are public-source facts, not immutable publisher or rights certificates; raw originals remain outside the repository.

The board uses `div.text-list > ul > li` rows, `div.text-ldata > div > p` month/day plus `span` year, and `div.text-linfo > h3` title / `p` excerpt. Seven source rows were observed, including a source duplicate for one article; source order is retained and no later ordinal is advertised. Articles use one `div.art-main`, direct `div.art-tit.cont-tit > h3`, `发布日期：YYYY-MM-DD`, and one `#vsb_content > .v_news_content` body. The adapter preserves active paragraphs and document-link hints without downloading attachments, rejects ambiguous containers and foreign/query/credential URLs, and keeps missing/invalid dates unknown. Full history, all-college coverage, image/OCR/table reconstruction, later pages and campus writes remain out of scope.

## Electronic Information Engineering source frontier

The official directory snapshot binds visible member13 电子信息工程学院 under 信息学科群 with exact literal/resolved `http://www.ee.buaa.edu.cn/`. Public read-only reconnaissance found the root-declared `/index/tzgg.htm` 通知公告 board, source-advertised `pb_sys_common` pagination, canonical `/info/1062/` article links, and the bounded selectors retained by the adapter (`ul.news-ul > li`, direct row `a`/`span`, and the direct `article-tt`/`article-sm`/`vsb_content` structure). This is source-contract discovery only; raw HTTP bytes and personal notice text are not committed.

The selected HTTPS candidate `https://www.ee.buaa.edu.cn/` is currently blocked before source admission: certificate SAN/hostname validation reports no alternative certificate subject name for `www.ee.buaa.edu.cn`; a separately probed canonical `ee.buaa.edu.cn` TLS handshake ended unexpectedly. Plain HTTP is not used as a fallback and no TLS verification is disabled. The adapter therefore truthfully exposes `college-source ee root|notices` as `surface_blocked` with `fallback_reason.code=tls_transport_blocked`, preserves the exact HTTP directory attribution and selected HTTPS candidate, and rejects EE listing/article reads as unsupported before transport. No board/article content, all-college/history/attachment coverage or online capability is claimed until a validated HTTPS source is available.
## Artificial Intelligence college announcements

The `iai` adapter binds the official-directory member 人工智能学院 while preserving its exact literal/resolved `http://iai.buaa.edu.cn/` identity. The source is deliberately observed over HTTPS at `https://iai.buaa.edu.cn/`; this is recorded as a separate observation, not an alias or silent protocol upgrade. The retained root declares `index/tzgg.htm` (通知公告), whose `mainBox/listText` direct `li > a + i` rows preserve source order, canonical `YYYY-MM-DD` dates and `/info/1024/<id>.htm` article links. The board's current pagination widget advertises no later ordinal, so page 2 and beyond remain unavailable rather than inferred.

IAI root/notices surfaces, listing filters and selected article reads use a dedicated allowlisted network profile and the shared directory/governor/cache policy. The observed article layout is `mainBox/nry2/form`, `show01/h5`, `show01/date/s`, and `vsb_content/show02/v_news_content`; source-declared `showVsbpdfIframe`/`vsb_pdf_image_data` content is reported as `embedded_document` or `partial_text` without fetching PDF/preview assets or fabricating text. No all-college/history/attachment/OCR or campus-write claim is made.

## Directory-bound Sepe energy notices

Local `work/sepe-announcements` starts at unmerged PR110 source `30f07060a2be4fc6a13f39c4207195776f60d9e9`. **No Sepe issue/PR, push, approval, merge or deployment is claimed.** The first PR110 reviews request failed with GitHub API quota403 at `2026-10-04T18:16:08Z`; no subsequent GitHub call, quota polling or alternate identity/proxy/anonymous fallback. External readiness is unavailable; private local status is retained while implementation advances.

Visible official-directory member3 能源与动力工程学院 under 航空航天学科群 retains exact literal/resolved `http://sepe.buaa.edu.cn/`; ordinal is source order, not a school code. Original directory HTML SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` differs from derived50-entry JSON SHA-256 `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. Selected HTTPS is a deliberate separate observation, not an upgrade, alias or verified protocol equivalent. Four active root links declare 公告公示 at `/xwdt/gggs.htm`; inactive JavaScript labels do not authorize a route.

Exactly four deliberate public GETs used the same permanent production governor, full fresh-deadline preflight and lease through body validation/hash/cache. The first source command exited8 after robots before absent root; later deliberate observations are not an automatic retry. All four private originals independently match base64/byte/hash checks in same-UID0600 single-link files under0700.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791139617317` |
| separately selected HTTPS root `/` | 200 | 56065 | `97c7fdc00efd21bf090ced686ea1ca91b644a3ed720041f00f565169e71a6551` | `1791139720141` |
| root-declared board `/xwdt/gggs.htm` | 200 | 29721 | `9b9b8ec8c3ae8221b6a44e750f63e813d5fd8d92e0820bb9a7a9d7394ac1043b` | `1791139952342` |
| board-declared original `/info/1078/2634.htm` | 200 | 32799 | `7e566e3777abefafdf12a135393fe996a33957f73ee4c8b9ed48937c7ff1c3b1` | `1791140925142` |

**Actual native content, not a fixture-only adapter:** cached listing preserves all nine source-ordered headings, full excerpts, dotted dates and literal/resolved links; inclusive2026-09-09 through09-30 selects three. The selected original privately matches its own heading, publication2026-09-30 and all55 ordered nonempty paragraphs. Its three active JSP file links are siblings outside the text body, retained as unfetched hints; result remains `partial_text`, with zero body tables/images. No personal headings/prose/file names are public/model input. The private event-ordered oracle matches the entire native output; a class-token/direct-child inspection mistake was corrected privately, not by changing Rust or replaying completed commands.

Reuse the existing Mse scoped `nymain/notice-list` parser, Chinese header-date parser and paragraph walk, not a second convention or shim. Extract the existing SCSE active JSP file-hint helper: SCSE keeps document scope, Sepe uses `art-main` to include its declared sibling files. Two new Sepe boundary/partial-content cases, eight existing Mse-module cases, ten existing SCSE/viewer cases and one parent active-attachment case pass: **21 focused cases**, not another full suite. Existing paragraph/body/governor budgets and nine `article_body` callers stay unchanged. Temporary original observer source is removed and its factory restored crate-private after real observation.

Actual refresh refusals all precede transport: unadvertised list page2 exit7, wrong category2, undeclared original3, original source_page2 exit7, uppercase/noncanonical host2 and foreign host with source_page1 exit2. Retained board declares no later ordinal; no filename, category or article is inferred. Root/board64-hint snapshots are explicitly truncated, not exhaustive discovery. Current source receipt governor SHA-256 `af4daa13f11071fe2caa3364e759d3a9148996896613b2085a7f9c12db753010` stays byte-identical through cache/refusal proof;60000/900000-ms floors, disarmed auth, no latch/pending/failures. Older Rse7bf/Mse68857 receipts remain historical.

No JSP download, table/image reconstruction, OCR, complete current/history/all-college coverage, campus write, auth attempt or policy bypass. Legitimate owner-controlled read/write capabilities remain included; current campus-write intent is none and assignment submission remains with the owner. Final command discovery, one bounded stateless no-tool feature check and actual local UI are distinct from exact-head platform approval. Broader non-VPN and every-college goals remain active; do not wait for external approval to advance reachable functionality.

**Completed single bounded feature check:** one fresh stateless no-tool completion received165,815 prompt characters: complete public Sepe/Mse/SCSE/announcements modules and supplied net profile/path/factory/main route/discovery sections. Result `no_concrete_findings`. Exact Main-bound supplied hashes and omissions are in `acceptance.json`; active-text implementation, transport/lease internals, organizations parser, other college/PDF-viewer modules, external dependencies, docs/acceptance and integration tests were not inspected. No private original/cache/personal text/auth configuration was supplied. This is not independently observed checkout/SHA/runtime/rights/CI or exact-head platform approval; no generic follow-up review loop.

**Final actual native and local-surface proof:** owned locked offline build0/30.09s; schema/help/capabilities and cached original all exit0. Sepe appears in command discovery, `gggs` college constraints and the declared1078/1093/1080 article pattern. All44 capabilities consume the new source/check evidence while announcements remains `partial-live-verified`. The entire55-paragraph/three-hint original output equals the durable private oracle; original hash/timestamp and governor bytes remain unchanged, with zero new campus GETs. Existing Mse under the new binary also returns `full_text`,339 rows/2331 cells and its retained original hash. A runtime-kernel state loss removed the in-memory old full Mse output; its durable receipt holds summary facts, so this last smoke does not assert entire old-output equality. Earlier equality receipts retain their original scope. Envelope inspection mistakes were corrected using already captured output, not command replay. Strict all-target clippy0/6.21s and formatter check0/0.86s pass; no new full suite.

Managed Chromium actually observed1365×900 and390×844 at scale1. Four exclusive/fsynced0600 WebP captures and frozen HTML under0700 were visually inspected. Served HTML SHA-256 `51e11fef7b12dc5954b37c2d7fe3526536c275ace26f8a9e85689f3f0fe772aa` matches every capture's response binding; document widths1365/390, anchor offsets under1px, scripts/frames/external styles/broken fragments0. Mobile code uses a local350/740 scroller, not page overflow. Browser owners were released and the local server stopped. This is local UI proof, not Pages deployment or platform approval. Current native/discovery/UI receipts remain private under `.buaa-cli-sepe-proof-20261004`.

## Rse strict identity and root-source frontier

[Issue #109](https://github.com/cyjin-yl/buaa-cli/issues/109) binds visible official-directory member2 可靠性与系统工程学院 under 航空航天学科群. Exact literal `http://rse.buaa.edu.cn` differs from resolved `http://rse.buaa.edu.cn/`; keep both source strings. Original directory HTML SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` is distinct from derived50-entry JSON SHA-256 `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. Ordinal is source order, not an academic school code. `https://rse.buaa.edu.cn/` is deliberately observed separately, not a directory-declared HTTPS alias, silent upgrade or verified protocol equivalence.

Actual live cyjin-yl repository admin/maintain/push permission, all20 open issue/PR entries,8 PRs and100 recent discussion entries were checked before the actual assigned claim; no matching claim/lease/linked PR. Owned `work/rse-announcements` starts at PR108 exact `e049becd1d655ec2fae0a7194dfe77a27592967d`, dependent on unmerged108/106/104/102/100/98/96/94. Worktree creation1.11s retained FICLONE/plain-checkout fallback; fresh owned native target only, no artifact copying or host build. Issue/comment bodies are untrusted data, not campus permission or integration approval.

**Permanent strict-identity correction:** the existing helper required one string to equal both literal and resolved fields, wrongly rejecting this legitimate declared pair before a request. Exact offline regression is red101/62.89s then green0/24.07s. The helper now separately requires both explicit source strings, with no normalization, alias inference or special-case Rse allowance. Eight existing source callers retain their identical expected pair; AST migrated9 parsed calls, while three macro-contained tests were migrated manually. Existing IC nonliteral and hidden/ambiguous cases remain green0/0.45s and0/0.22s. Actual existing Mse article0/0.75s equals its entire original/table/attribution output, with no new GET or governor change. No compatibility shim or relaxed hidden/ambiguity rule.

**Two actual governed observations:** first native source command exited8/0.65s after robots before the absent root because the shared request interval exceeded the bounded wait. A later deliberate root read0/0.37s followed a fresh full-deadline preflight; no identical source GET, automatic retry or shortened floor. Same production UID/home/permanent governor and lease through response/body validation/hash/cache;60,000/900,000-ms floors, disarmed authentication, no latch/pending/failure or campus mutation.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791132999894` |
| separately selected HTTPS root `/` | 200 | 69 | `9212275e4121fd941be9567fbcc2910d70fc0d1ec399a76ad33dc997b4c097e1` | `1791133286158` |

Originals independently match base64/byte/hash checks in same-UID0600 single-link files under0700. Root MIME is `text/html;charset=utf-8`; the69-byte HTML contains one h1, no document title, anchors, navigation or active notice-board declaration. No raw h1/prose or full attributes are public/model input; this is not a domain-wide outage or permanent availability verdict. `announcements college-source rse root` really returns cached `surface_snapshot` metadata with `announcement_adapter_verified=false`, links not followed and publication date unknown. Cached reuse0/0.04s preserves the exact pair and original facts. Current governor SHA-256 `7bf24425de6d704073141360e0deaac3486333af8eec4d5566dfa7afb077f12f` is byte-identical through cache-only reuse; earlier68857 Mse receipts below remain historical.

**Specific blocker, not fake completion:** no root-declared notice board exists in the retained selected HTTPS response, so no source-bound listing/original target can be observed. Need a usable current root declaration or explicit reviewed current source contract. No guessed index/notice/article path, source alias, HTTP fallback, script execution or protocol-equivalence assertion. Rse notice implementation and original verification remain blocked, not dropped/completed; no Rse list/article adapter is advertised. Reachable strict source-pair binding and real fixed root metadata are implemented, not a generic success stub or working-notices claim. Full every-college/current/history/attachments and non-VPN goal stays active; move to other substantive work rather than repeating these GETs or waiting/polling integration.

Fresh owned native build0/82.08s passed; first actual offline root7/0.95s reached a genuine cache miss. The proof script initially looked for internal `offline_miss`; actual CLI maps it to `unavailable` with a cache-miss message. Corrected only that envelope inspection using retained output, without command replay or wording-pinning test. Metadata, actual local UI and exact-head publication remain separate proof, not an additional full-suite run, independent approval or deployment. Legitimate owner-controlled read/write scope stays included, current campus-write intent none and assignment submission remains owner-controlled. No subagent or peer revival.

**Completed bounded source check:** one stateless no-tool completion,14,509 prompt characters, returned `no_concrete_findings`. Complete public Rse module and changed shared identity/surface/HTML/profile/factory sections were supplied. Main binds Rse module SHA-256 `7a60a339ab895cb19a7af3e7b3ee6ccbff36d94e4355117414eceac8f7bae71a`, announcements `79438a15965d02c60e3a0a79c6401eaf56a4eb5405f2877f660960a5fbac11eb` and net `3cdc498923fd3d234b1b6643fe16e76e259b3e1cd91c2e793b27abd53eb3af92`; no independently observed checkout/SHA/runtime/rights/permission/CI or platform approval. Omitted legacy bodies, caller/test migrations, transport/lease internals, docs/acceptance and external dependencies were not reviewed. Prompt's common MAX_URL4096 statement was incorrect: actual unchanged code uses16KiB, while Rse only allows fixed short root/robots paths. No route or policy expansion follows; this correction is explicit rather than another generic source sweep. Root/original source bytes and prose were not review input.

**Final native/discovery/refusal proof:** after truthful root-only schema/help and acceptance metadata, locked offline native build0/26.67s passes. Actual cached root0/0.10s, schema, help and capabilities all succeed; entire cached root output remains equal.44 capabilities consume the exact root evidence, notice blocker and bounded source-check scope while retaining announcements `partial-live-verified`. Actual Rse notices/list/article refresh attempts each refuse2 before transport, with unchanged governor bytes and no new campus GET. Strict all-target clippy0/22.74s and formatter check0/0.91s pass. These are focused existing/new authority cases and real API proof, not an extra full-suite, independent platform approval, protocol fallback or working-notices claim.

**Actual local UI proof:** managed Chromium1365×900 and390×844, scale1, observed the root-only example and current source evidence. Four exclusive/fsynced0600 WebP captures and frozen HTML under a new0700 private folder were visually inspected; both served sources match HTML SHA-256 `7aeb8d10ac523b92132e1fa0bee69d4113f2d115343f3a469d842c8304ed808c`. Literal/resolved strings, root69-byte/no-declaration facts, unverified adapter, blocked notices/originals and current refusal/check scope are visibly separate from older Mse table proof. Document widths1365/390, evidence-anchor tops below1px, scripts/frames/external styles/broken fragments0; mobile code is a local350/514 scroller. Initial raw screenshot execution timed out60s with zero captures; foreground ownership/direct screenshot recovered the first image, immediately preserved outside `/tmp`, and only the remaining captures were taken. Inconsistent observe viewport metadata was reported; actual page/pixels show requested dimensions. Tabs/server released, older receipts untouched. Local proof, not deployed Pages.

## Source-ordered Mse table text

Bounded [issue #107](https://github.com/cyjin-yl/buaa-cli/issues/107) closes the known nonparagraph table-text gap in the already retained Mse original, not a new endpoint, source crawl or fixture-only adapter. Owned `work/mse-table-text` starts at PR106 exact `bb2dad9fb359718ed73bc9950c3bd75b804b1350`; PR106 and PR104/PR102/PR100/PR98/PR96/PR94 remain unmerged. Root-main, parent worktrees/binaries and deployed Pages are unchanged. External exact-head approval, trusted checks and maintainer stack decisions remain separate gates; implementation proceeds without polling or waiting for them.

The actual cache-only `announcements article` succeeds with **one source paragraph, one table,339 rows and2331 cells**, now `full_text` instead of PR106's explicit missing-table `partial_text`. Every caption/cell/header/declared span privately matches the same retained HTML; original heading/date/paragraph/retrieval and directory attribution remain unchanged. No personal headings, cell text or full source attributes are public fixtures, model input or diagnostic output. Original522,352-byte HTML SHA-256 `dfbf74173c1a9d57a5e59e15b70de706874ee8fa4c692ced8366a27fbd0ffcb3`, fetched at `1791096587326`, stays an original-byte provenance fact, not a hash or publication date of derived text. This feature sends **zero new campus GETs**; production governor SHA-256 `68857c0a5646124c69aaee3392169e3d23ee04a3582b6affac2c787fc4685eab` remains byte-identical.

`body_tables` represents separate source-ordered tables, nullable captions, rows and cells. Cell `header` is true only for original `th`; normalized active text and explicitly present DOM-decoded `rowspan`/`colspan` strings are retained without defaults. `body_table_count`, `body_table_row_count` and `body_table_cell_count` expose aggregate counts. No inferred cells, span expansion, visual-grid or paragraph/table interleaving reconstruction. Paragraph-wrapped cells remain in `body_paragraphs` as well as the separate records. Ordinary table-only text is supported; empty/nontext bodies, nested tables and unowned nonempty table text fail closed. Images/attachment contents remain partial/unfetched; no OCR or complete-history claim.

Budgets are unchanged or shared conservatively:2-MiB HTML; source paragraphs plus table rows count against1024 blocks, at most256 tables/cells per row,8-KiB normalized row/caption text and512-byte declared span strings. Overflow is an error, never truncation. Other college/news callers pass false for additional source text and retain their existing nonempty-paragraph admission; only Mse uses already extracted nonempty table text. Existing active-text/inert helpers are reused rather than adding a second convention.

Actual affected proof:66 announcement cases pass0/44.90s including compilation (test execution0.14s); initial nine Mse cases expose one old real-loopback partial-table/cache expectation101/1.28s. Migrating the consumer assertion to full text and cache-retained cell records yields nine passing cases0/32.74s. Two new uncertainty cases cover mixed inline order/inert scope/declared spans and1024/1025-row overflow. Strict all-target clippy0/19.11s and formatter check0/0.54s passed before the typed-schema edit. No generic source-review loop or additional full-suite run; earlier250/251/252+19 and all parent receipts below retain their own scope.

The first private proof helper stored direct text separately from children and reordered mixed inline cells, creating279 false comparison mismatches. An event-ordered private oracle matches every cell and span against the already captured native result; native code/data were not changed to accommodate the broken oracle and completed commands were not replayed for that repair. Originals, failed comparisons and corrected proof remain private. Worktree creation2.74s retained FICLONE/plain-checkout fallback. Artifact copying failed1/51.13s on mode preservation and remains recorded; a fresh owned `target/native` built0/73.52s instead, without chmod, repeat copy, parent overwrite or host build. First actual cached article exits0/0.65s.

**Typed machine/native proof:** first typed-schema build101/6.55s reached the existing `json!` macro recursion limit. Moving the same properties Value into a separate existing-style assignment built0/17.56s; no crate-wide recursion increase or table-record copy. Actual `schema`/`capabilities` each exit0/0.02s and expose typed captions/rows/cells/header/span/count fields.44 capabilities consume the feature metadata and keep announcements `partial-live-verified`; this is not independent full JSON-Schema-validator certification. Actual cache-only article0/0.61s equals the entire earlier table output and every private source record, with unchanged governor bytes.

**Single bounded feature finding and correction:** one stateless no-tool completion received the full public Mse module and complete affected shared admission/output/schema/active-text functions,52,755 prompt characters. Main-bound Mse SHA-256 `7b7bd6a78caad91abcf9c5c053b2f5de8e87cf21ffe7073bf8850070daae3a2c` and announcements SHA-256 `340a259aa737e00cb3f3e7998413bfc339ce4c7b5b694701aada9af25a602c6f` identify supplied pre-correction bytes, not an independently observed checkout or final-head approval. No legacy/PDF/network/governor implementation, private original/cache, runtime, rights, permission or CI observation. MSE-TABLE-001 is accepted: `char::is_control` incorrectly refused source-present entity-decoded newline/tab span strings under the raw-string contract. Exact synthetic reproduction is red101/16.46s,0passed/1failed. Removing only that rejection retains the512-byte bound and original strings; JSON escapes output-only strings rather than interpreting spans. All **10 affected Mse cases pass0/24.31s** (execution1.33s), including the new regression; strict all-target clippy0/8.01s and formatter check0/0.79s pass. Final code includes this accepted correction/regression and the move-only schema split; no generic re-review or extra full-suite run. Source/caption/cell facts and current account policy remain unchanged.

**Corrected final metadata/native proof:** after the span correction and acceptance metadata, the owned locked offline native build exits0/51.62s. Actual final schema0/0.04s, capabilities0/0.03s and cached article0/0.73s all succeed.44 capabilities consume the current10-case proof and accepted finding response while keeping announcements partial. Parsed schema output is identical to its earlier typed contract; the entire article output and every private source record remain equal. Same original hash/timestamp and governor bytes; zero campus GETs or extra full-suite run.

**Current actual local visual proof:** managed Chromium1365×900 and390×844, scale1, observed the updated article example and feature evidence. Four exclusive/fsynced0600 WebP captures and a frozen HTML copy under a new0700 private folder were visually inspected; both served responses match HTML SHA-256 `364a52ed96eb5256b5aabfce4026dabd4bd99ee74b4d1a8d6def59752819720f`. Current339-row/2331-cell full-text/source-table facts and10-case correction are separate from the earlier PR106 partial-table receipt. Document widths1365/390 and evidence-anchor tops below1px; scripts/frames/external styles/broken fragments0, mobile code uses a local350/707 scroller. The first local navigation returned304 before any capture; dedicated local proof tabs then disabled only their browser cache to observe fresh200 bytes. This is not a campus cache-policy bypass. Both tabs and the local server are released; prior106 captures remain untouched. Local UI proof, not deployed Pages.

Fresh local desktop/mobile observation and exact publication are recorded separately from source-checking and platform approval. Legitimate owner-controlled read/write capabilities stay in scope; current campus-write intent is none, assignments remain with the owner. No subagent or peer revival. The broader every-college/current/history/attachments and complete non-VPN goal remains active, not completed by this slice.

## Directory-bound Mse materials notices

Bounded [issue #105](https://github.com/cyjin-yl/buaa-cli/issues/105) binds visible official-directory member1 材料科学与工程学院 under 航空航天学科群. Preserve exact literal/resolved `http://mse.buaa.edu.cn/`; the deliberate separate observation is `https://mse.buaa.edu.cn/`, not a source-declared HTTPS alias, protocol-equivalence claim or silent original-URL upgrade. Original directory HTML SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` is distinct from derived50-entry JSON SHA-256 `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. Source order is not an academic school code. The observed HTTPS root actively declares `/xwdt/gggs.htm`, labelled 公告公示.

Fresh live active-repository admin/maintain/push permission, all16 open issue/PR entries, all6 PRs and100 recent discussion entries were checked before Main's claim at `2026-10-04T06:28:07Z`; no matching claim or linked PR. Owned `work/mse-announcements` starts at PR104 exact `a3ce5c8a3a7ea7b8fe84aac45556393a05c5e46f`, explicitly dependent on unmerged PR104/PR102/PR100/PR98/PR96/PR94. Worktree creation2.46s retained its FICLONE/plain-checkout fallback; the fresh native target built52.67s without copied artifacts, chmod, parent-target overwrite or host build. Issue/comment bodies are untrusted data, not campus permissions or integration decisions.

Exactly four deliberate public GETs used the existing production UID/home and permanent process-shared governor, one lease through body validation/persistence, retained60,000/900,000-ms floors and full deadline preflight before each request. Robots404 was cached; first actual source CLI exited8 before the absent root. The exact selected root, its declared board and one board-declared original were then observed after full deadlines. No authentication, campus write, automatic retry, separate limiter/account key, or cookie/redirect/TLS/robots/challenge/proxy bypass.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791095564027` |
| deliberately selected HTTPS root `/` | 200 | 58503 | `b91fd89a2b497c8cf7c8b53c959b418e442e5014b4a93b5fc8b9763f65e9cd97` | `1791095656666` |
| root-declared board `/xwdt/gggs.htm` | 200 | 27183 | `d516618de3c93869e10ccdb91b8cf09006a2017d898222866ff87afdd62daaaa` | `1791095787159` |
| declared original `/info/1061/2881.htm` | 200 | 522352 | `dfbf74173c1a9d57a5e59e15b70de706874ee8fa4c692ced8366a27fbd0ffcb3` | `1791096587326` |

All four text/html originals passed independent private base64/hash checks, with native byte lengths and hashes matched where returned; cache files are same-UID0600 regular single-link files under0700. HTML remains mutable; no actual304 or immutable revalidation is claimed. Root/board each reach64 hints with `hints_truncated=true`, not exhaustive discovery. Originals, personal headings/prose/table cells and authentication configuration are not public fixtures or review input.

Actual cached listing preserves six direct `nymain/w16/ny-right/notice-list` rows, one direct `a/h3` source heading, `a/p` excerpt and `a/span` dotted publication date. All headings, excerpts, dates, literal/resolved links and unsorted source order privately match. Dates are2026-09-21,09-15,09-09,09-15,09-14,07-27; inclusive2026-09-15 through21 selects3. Missing, invalid or duplicated date spans stay null and cannot satisfy a date filter. Both1061/1058 article categories are declared, not guessed. Scoped `notice-list/pagestyle/p_no` advertises ordinal2 at `/xwdt/gggs/4.htm`, then3/4/5 at filenames3/2/1; none was fetched live or inferred. Actual page2 offline/page6 refresh/wrong category refusals are7/7/2, without GET or governor change.

**Excerpt correction:** initial real cached list/filter both failed7 because a copied512-byte heading bound was incorrectly applied to source paragraph excerpts of534/583/595/440/571/517 UTF-8 bytes. A correctly selected synthetic consumer case reproduced red101/1.45s, then passed0/10.32s after Mse excerpts used the existing8-KiB paragraph budget without truncation.600-byte UTF-8 and8192-byte full excerpts are retained;8193 is rejected. Heading512/href4096/entries256/HTML2MiB and shared1024-paragraph/8KiB budgets are unchanged. An earlier unqualified `--exact` invocation ran zero cases0/19.79s and is not proof. Corrected native build0/8.19s/list/filter0 privately match6/3 with unchanged governor bytes; no campus GET was replayed.

The temporary original observer used actual offline directory/root/list admission and the real shared-governor client, refused undeclared42/exit3 without a request, then retained one declared original with `text_adapter_verified=false`. Initial example compilation101/5.97s called unstable str.as_str on an already-static str; correcting the actual type built0/2.84s. After actual cached extraction, the source was removed and the factory restored crate-private. No second original GET or live text-parser refresh. A private-cache proof helper initially confused output retrieval fields with stored cache fields; corrected `body_base64`/`sha256`/`status`/`headers` names without replaying completed commands.

The original has one direct `nymain/w16/ny-right/form/art-main`, its own `art-tit/h3` heading, one `p/span.date` with `日期：2026年09月21日`, and unique `art-body-box/art-body/ar_article#vsb_content/v_news_content`. The original heading differs from the listing teaser and is never substituted. One156-byte nonempty source paragraph privately matches. The table has339 rows/2331 cells without paragraph wrappers, so `partial_text` explicitly reports one unextracted table; no invented full-table text. Zero images or attachment hints in this sample. Paragraph-wrapped table cells are retained in source order; other table text, images and attachment contents remain unextracted/unfetched. Table-only/empty bodies remain unavailable under the unchanged nonempty-paragraph admission. Actual article0/0.38s after native build0/11.04s preserved heading/date/paragraph/hash/length and governor bytes, with zero new GETs.

Six focused synthetic/parser/real-loopback cases pass0/21.00s, including compilation; test execution0.47s. They defend full excerpt bounds, source order/ambiguous dates and filters, primary view/heading ambiguity, original header versus body dates, missing table content versus paragraph-wrapped cells, active scoped ordinals, and only-selected board-declared mixed-category refresh/offline reuse. Full source gate, stateless source checking and exact-head external integration remain separate evidence. The broader every-college/faculty/full-text/attachment/history goal stays partial and actionable. Legitimate owner-controlled campus writes remain included in scope, but none is requested or needed here; assignment submission remains with the owner. No subagent, merge, issue closure, trusted CI or root/Pages deployment claim.

**Coherent source gate:** locked offline build, full **250 library + 19 CLI tests**, two intentionally ignored workers across five suites, strict all-target clippy and formatter check passed. Separate command boundaries: formatter0.97s/build11.43s/full tests82.57s (library71.67s, CLI0.19s)/clippy18.54s/formatter check0.63s. Six focused21.00s cases above and intermediate native builds are not extra full-suite runs. Prior Iiif244/Zfai238/H3i232/Shenyuan228/Beijing224/aviation220 plus19CLI receipts retain their previous heads. Production governor SHA-256 `68857c0a5646124c69aaee3392169e3d23ee04a3582b6affac2c787fc4685eab` stayed unchanged through this offline gate, with60,000/900,000-ms policy, disarmed authentication, no latch/pending outcome or failures. No new campus request. Fresh public-source check, actual local visual proof and exact-head external publication/integration remain distinct from this gate, not inferred approvals or trusted CI.

**Actual metadata/native/local visual proof:** after250+19 metadata, owned native build0/5.98s and eight actual cache-only commands0 returned root/board/list/filter/article/help/schema/capabilities. Source6/3/1 partial-text/title/date/ordered excerpts/paragraph/retrieval privately match;44 capabilities consume the actual gate and keep announcements partial. Actual article undeclared-refresh/source-page6-refresh/noncanonical/offhost-with-source-page refusals3/7/2/2 precede transport with unchanged governor bytes. A proof-script schema-envelope KeyError was corrected to `commands.announcements` using retained output, without replaying the eight commands or claiming separate JSON-Schema validator certification. Actual managed Chromium desktop1365×900/mobile390×844 observations and four WebP captures confirm Mse examples, explicit HTTP-versus-HTTPS relation,6/3/1 partial text, unextracted339-row/2331-cell table, truncated hints, unmerged104/102/100/98/96/94 and250+19/prior-head scopes. Fresh evidence-link clicks place the heading within1px of viewport top; document widths1365/390, scripts/external styles/frames/broken fragments0, mobile code remains a local350/681 scroller. Four exclusive/fsynced0600 current-UID single-link captures under0700 plus observed HTML are preserved outside source/tmp; HTML SHA-256 `e187b9c428917838324cb5957fac54e73f8137c552d02526f2a073c7a560c9f9`. Both managed tabs were released and the local docs service stopped normally. No new campus GET, deployment, formal approval or trusted CI is inferred.

**Fresh source-check scope and accepted correction:** two stateless slow-backend attempts returned no usable output:16 complete public Rust files506,557 characters failed with no structured response; a distinct schema-free7-file339,799-character attempt failed with no text. Both are retained failures, not checks passed, findings or approvals; tool QA reports were filed. A separate session-default, no-tool plain-text check of those seven complete public files actually returned MSE-001 at Main-bound source `883ddbc355c17e4dd225b747252559356b538ab7`. Supplied: Mse, announcements, net, main, organizations, governor and html. Omitted: nine separate legacy college/PDF-viewer modules, docs/acceptance, integration tests, unlisted modules and external crate implementations. Main bound bytes/head; the checker did not independently observe checkout, SHA, runtime, originals/cache, rights or CI. It correctly traced nested article Result/cache semantics, not an original-cache-loss claim.

MSE-001 is accepted: the common transport's second cache load, after acquiring the request lease, used `Outcome::Success` for a local cache error before sending HTTP and erased an existing shared network-failure streak. A real isolated Mse-profile loopback reproduction creates failure1 with a truncated response, expires only synthetic timers, validates an initial retained cache then corrupts it before the under-lease reload. Red101/26.97s observed0 instead of retained1, without another HTTP request for the cache error. The transport now reuses the existing `finish_without_request` completion used by gateway local preflight, preserving the cache error, failure history and reserved request gap. Green0/5.44s retains failure1, sends no extra target request for the cache error, then a second actual loopback truncation increments failure2 and schedules more than59 seconds of backoff. Seven focused consumer/loopback cases pass0/1.23s (execution0.89s). No governor state implementation, identity, policy/floors/latch/authentication or production state was altered; zero campus GETs.

**Corrected coherent gate:** after MSE-001, locked offline build/full **251 library + 19 CLI tests**, two ignored across five suites, strict all-target clippy and formatter check pass. Separate formatter0.88/build8.43/fulltest77.67 (library64.93, CLI0.19)/clippy8.67/fmtcheck0.70 seconds. Initial250+19/full82.57 and four initial visual captures above keep883 source-head scope; they are not renewed-head approval or extra full-suite evidence. Production governor `68857c0a5646124c69aaee3392169e3d23ee04a3582b6affac2c787fc4685eab` remains byte-identical. A changed source head requires a renewed source check and exact-head integration gates; no approval, source deployment or merged-root safety correction is inferred.

**Follow-up source finding MSE-002:** the completed renewed stateless no-tool check of the same seven complete public Rust files (342,641 characters) at Main-bound `4a03e282feddc3505a26833beb408f747f62e148` reported one concrete pagination ambiguity. It had the same omitted nine legacy college/PDF-viewer modules, docs/acceptance, integration tests, unlisted modules and external implementations; no checkout, runtime, private originals/cache, rights, trusted CI or platform approval observation. Two active scoped declarations of ordinal2 with different allowed destinations made the shared helper silently select the first. A synthetic regression reproduced red101/26.29s; after scanning all active matching ordinals, it passed0/6.31s. Distinct destinations now return unavailable; identical declarations retain the one declared URL. University/scse/ic/aviation/Beijing/Shenyuan/Zfai/Iiif/Mse callers keep their existing selectors and URL predicates. The existing identical-declaration assertion and seven Mse cases pass, the latter0/1.07s. No guessed or additional page GET, changed source facts or relaxed governor policy.

**Latest coherent source gate:** after MSE-002, locked offline native build0/7.94s, full **252 library + 19 CLI tests** with two ignored across five suites, strict all-target clippy and formatter check pass. Separate formatter0.88/full tests74.71 (library70.39, CLI0.29)/clippy7.79/fmtcheck0.59 seconds. The proof script's assumption that the second suite was CLI was corrected using the completed output: the empty binary suite precedes CLI. No command replay or second full-suite run. Actual rebuilt cache-only list0/0.51s, advertised uncached page2 refusal7/0.13s and original article0/0.36s privately equal their entire retained outputs. Original6/3/1 partial-text facts and the large missing table remain unchanged. Production governor `68857c0a5646124c69aaee3392169e3d23ee04a3582b6affac2c787fc4685eab` stays byte-identical; four campus GETs total, no new GET/auth/write. Initial883/250+19 visual proof and4a03/251+19 gate remain earlier scopes, not visual proof of252 or independent approval. Corrected-source checking, current local visual proof and exact-head external integration are still distinct gates.

**Final affected-source correction and delivery boundary:** the next completed seven-file source check at74820 reported MSE-003. Its nested-template-anchor-only recipe was already unavailable before the fix; actual red101/23.60s instead demonstrated whole inactive directory groups being emitted and inactive fallback text contaminating category labels. Reusing the existing active/inert text walk in `html` excludes inactive groups, headings, members and inline payloads without a second extraction convention. Green0/15.34s retains only active labels and the exact HTTP member; the old hidden/missing/non-HTTP controls remain intact. Only affected locked offline commands were run:4 directory cases0/0.50s,64 announcement cases0/0.51s and7 Mse cases0/1.04s; these sets overlap, not a new full-suite total. Native build0/15.78s, strict all-target clippy0/9.33s and formatter check0/0.70s passed. Actual cached `organizations list`, Mse list/filter/article all exit0 (0.09/0.17/0.11/0.39s); directory50 entries retain original HTML SHAf491e3a and entire Mse6/3/1 outputs privately match. Production governor68857 remains byte-identical and four campus GETs remain the total. Prior full252+19 stays74820 evidence, not a253-full-suite or current platform approval claim. No further generic source sweep or repeated full-suite gate; publish the bounded implementation and responses, keeping exact-head approval/integration separate.

**Current local visual proof:** sourceb5a816 was observed in actual managed Chromium at1365×900 and390×844, scale1. Four exclusive/fsynced0600 WebP captures under a new0700 private folder were visually inspected; both served responses match frozen HTML SHA-256 `02adf619ecd16f9dd9eccd788a4e3801a3cb795897b31732dec978f7d5be6f7c`. Examples show the exact HTTP identity/separate HTTPS observation and6/3/1 partial-text/table limits. Evidence distinguishes current affected proof from74820 full-suite scope and preserves owner write/submission boundaries. Document widths1365/390, evidence-anchor tops below1px, scripts/frames/external styles/broken fragments0; mobile code remains a local350/681 scroller. Earlier R2 documented-helper timeout/viewport mismatch created no captures; its frozen HTML remains, not visual proof. Both managed tabs were released and the local server stopped. No Pages deployment, additional campus GET, formal approval or trusted CI claim.

## 2026-10-02: current safety frontier

The earlier blocker table and dated receipts below are historical observations, not a current domain-wide egress verdict. Public SPOC pages and one source-declared script, university news, computer-college/integrated-circuit-college notices and an original policy PDF were later read through the shared governor. Authenticated campus contracts, rights-cleared recording/Life inventory, the current skills-fs Go contract, private CI runner/signing trust and full devcontainer runtime proof remain separate gaps.

An initial offline review under the existing permanent lock found private single-link version-2 governor history from a different Linux boot. Its SHA-256 was `1053b98f11dfcf1ce964eed2d9fec1635f65bbcabf9565b70c2427a231500850`; request/background policy was 60,000/900,000 ms, with known outcome, no armed authentication, and no rejection latch. No cross-boot UTC anchor exists. Recorded request/cooldown residuals were 60,001/31,309 ms relative to its old last observation; those are **not current wait durations**. During that review the history stayed byte-identical and zero requests were sent. The deliberate migration below now resolves this environment's boot mismatch; a future mismatch still fails closed.

[Issue #83](https://github.com/cyjin-yl/buaa-cli/issues/83) binds the original `governor boot-review-plan` / `boot-review-commit --offline` implementation. A typed, exact preview is rechecked under the same permanent account lock. Complete old bytes are durably retained without overwrite before atomic migration. Full old residual delays are newly reserved with no elapsed-time credit; raised policy gaps, rejection latch, network failures and saturated deadlines remain protected, and authentication permission is disarmed. Unknown outcomes and missing/corrupt/partial history cannot be cleared by this flow.

Development proof: the actual CLI preview exited 0, schema exposed the local-only contract, and online commit/malformed input/incorrect intent failed with exits 5/2/5 before state mutation. Six offline safety regressions passed, including original-byte retention, full delay carryover, latches/unknown outcomes, saturation, stale/tampered plans, partial snapshot refusal, exact crash-snapshot reuse and completed replay refusal. A stateless, no-tool fresh-context source check found no concrete implementation defect and identified masked admission coverage; tests now expire only synthetic waits before exercising authentication/latch denial and verify retained failure history through the next observed backoff. This check is not a platform approval or runtime test. Final locked offline build/test/strict-clippy/formatter gate passed: **197 library + 18 CLI tests, two ignored**, across five suites. The gate alone is not a production migration or campus request receipt. The current user stopped subagents; none is running or being revived.

**Actual local migration:** [PR #84](https://github.com/cyjin-yl/buaa-cli/pull/84) merged exact source `4b18ebfa6c69d504d8ad5aaee991b6545db956a2` into `35e37edd2524785a1a6a88ce436ff64435a9d4f2`; [source QA/maintainer decision](https://github.com/cyjin-yl/buaa-cli/pull/84#issuecomment-5950136014) is not a formal GitHub self-approval. The rebuilt merged CLI deliberately committed the exact typed preview once. Complete original bytes remain in a private mode-0600, current-user-owned regular single-link snapshot, verified byte-equal with the hash above. Current boot binding, 60,000/900,000-ms policy, failure/latch history and disarmed authentication were retained; full request/background/cooldown residuals of 60,001/900,000/31,309 ms were newly reserved without elapsed-time credit. Repeating the completed commit returned conflict/exit 9 without changing current state. Zero network requests or authentication attempts occurred. [Operational receipt and completed bounded issue #83](https://github.com/cyjin-yl/buaa-cli/issues/83#issuecomment-5950488113). No reset, history deletion or alternate account key. Comprehensive real power-loss/fsync/rename fault injection is not claimed.

**Post-migration selected-page proof:** actual `buaa announcements list --refresh` with `{"category":"tzgg","page":2}` first cached stale robots as HTTP 404 and stopped with exit 8 before the target request. After independently checking the retained global deadline, one deliberate observation returned HTTP 200 for the source-advertised `https://news.buaa.edu.cn/tzgg/252.htm`: five entries, 20,663 bytes, SHA-256 `15c6f575d4bb0a9a2a1af031a23663b4f588857dc42928b2c132f53f562fd95e`, fetched at `1790937766430`. Offline reuse returned the same hash and five entries. A later deliberate conditional refresh, after the global gap, returned `cache_status=revalidated`, status 304 at `1790938399051`, preserving original timestamp/hash. Latest-page discovery stayed cache-first; selected target refresh used the same source/cache/governor identity. No retry loop, auth, mutation or pacing change. This proves one selected university page, not all-college/history completion.

**Merged bounded source slices:** news [#73](https://github.com/cyjin-yl/buaa-cli/pull/73#issuecomment-5934270599) (`f3ab33bad3e53865749308882f1e73aec34fadae`), computer-college [#79](https://github.com/cyjin-yl/buaa-cli/pull/79#issuecomment-5941892130) (`86d7dc33603337c77dbd2a268c649911774ad0d4`), original PDF [#81](https://github.com/cyjin-yl/buaa-cli/pull/81#issuecomment-5942853948) (`30f11afedba36e711bbb002f5775962d0e6035b2`), and School Six [#77](https://github.com/cyjin-yl/buaa-cli/pull/77#issuecomment-5943701603) (`ef0e84508a3035b44673d71f0dce97eaea481333`) have exact-head independent source review plus explicit maintainer decisions recorded before merge. Those independent reviews predate the stop-subagent instruction. Live REST confirmed these exact merged heads and empty inline review comments; Copilot quota-limit comments are not approvals. Aggregate announcements/credits acceptance remains partial. Missing official policy, other college/attachment/history coverage and rights-reviewed recordings remain missing.

## 2026-10-02: source-bound public SPOC script

Bounded [issue #87](https://github.com/cyjin-yl/buaa-cli/issues/87) adds explicit `spoc surface root|entry` selection and `spoc script` JSON-URL metadata reads, not an authenticated adapter. Source binding uses active same-origin declarations from the retained entry, first-base/inert/type rules and the reviewed fingerprinted JS grammar. Entry discovery remains cache-first; only the selected immutable script may refresh, on the same cache/profile/governor. Bodies/configuration stay private; no script execution, endpoint inference, auth, course/media operation or account-policy change.

Actual production CLI first refreshed stale SPOC robots HTTP 404 (431 bytes, SHA-256 `270d2fb55aa801662897590a27ec1c152407fa36be1d6678c27fd8c1859239e4`) and exited 8 before the selected request on the retained 60-second/30-second wait bounds. One later deliberate old-script request returned unsupported HTTP status/exit 7 with no cached bytes; its exact status is not exposed. There was no identical retry. Entry-only refresh then returned HTTP 200, 2,173 bytes, SHA-256 `f728b87eb8579c7e1fa6ce689cbc1b85d30b2cbdda68a07add42bae00c081ba9`, fetched `1790950297351`, with new app/vendor declarations. The retired app URL now fails source binding offline/exit 3 without governor mutation.

After independently checking the full shared deadline, the explicitly declared `https://spoc.buaa.edu.cn/spocnew/js/app.a7c0879c.js` returned HTTP 200 `application/javascript; charset=utf-8`: 2,424,757 bytes, SHA-256 `5df4a46bb0277e60094ed1f2536a52e28a422558cb525fc28b1945ef8d7fa038`, fetched `1790950469253`. Independent private-cache base64/length/hash and immutable-flag checks matched. Actual offline CLI reuse returned the same source/script hashes, bytes/timestamp and a cache hit with unchanged governor state. Vendor bytes were not fetched. Filename fingerprint is not a checksum; no signature, syntax or external checksum validation is claimed.

Focused offline proof: nine library plus one CLI cases passed for source binding, real loopback selected-only refresh, private output, first-base/inert rules, URL/resource bounds and wrong-MIME/cache-poisoning refusal. A separate regression failed on Unicode type/URL trimming and passed after sharing the existing PDF viewer's HTML ASCII/explicit-type admission and retaining literal `src` provenance. Full JSON-Schema validator was unavailable; schema JSON was inspected, not independently validator-certified. Current request/background policy remains 60,000/900,000 ms with disarmed auth, no latch/pending outcome and no reset/key split. No subagent was started or revived. [docs/SPOC.md](SPOC.md) retains exact facts and prior observations. The aggregate SPOC acceptance item and [#42](https://github.com/cyjin-yl/buaa-cli/issues/42) remain blocked/open pending an owner-reviewed course/session/material contract, private credential delivery and rights-cleared inventory.

Final source gate after tightening MIME authority: locked offline build, **205 library + 18 CLI tests** (two ignored, five suites), strict all-target clippy and formatter check passed. Missing source HTML MIME was reproduced red, then refused before any selected request; exact media-type matching rejects HTML-prefix lookalikes, and all twelve focused SPOC cases passed. Actual corrected native offline use retained typed entry/script provenance and unchanged governor state. Earlier actual `script --refresh` returned revalidated HTTP 200 at `1790952887461`, with immutable bytes/hash/original timestamp preserved and entry discovery still a cache hit; no 304 is claimed. Root-only/entry-only offline CLI, help/schema/capabilities succeeded. Twelve changed public files had zero bounded credential-format scan hits, not a comprehensive security verdict. Full authenticated SPOC acceptance is not completed by these proofs.

**2026-10-03 current-main reconciliation:** the owned SPOC branch now includes main `04ec77a06a00283da24bf7f3636c6edf6a6d60c9`, preserving the IC source, shared inert attachment fix and source-page/redaction regression alongside SPOC script admission and selected-page support. Nine actual native cache-only commands passed: script, root/entry/default surfaces, IC policy article and notice-source metadata, help/schema/capabilities. Original entry/script hashes and timestamps matched; IC retained its policy title/date and 38 paragraphs. Shared governor bytes stayed unchanged with 60,000/900,000-ms policy, disarmed auth and no latch/pending outcome. No new campus request, authentication or mutation.

The combined locked offline gate passed **213 library + 19 CLI tests** (two ignored, five suites), strict all-target clippy and formatter check; twelve focused SPOC cases, both IC transport/cache cases and source-page/redaction CLI proof also passed. Prior 205+18 receipts above remain prior-head evidence. At this pre-correction checkpoint [PR88](https://github.com/cyjin-yl/buaa-cli/pull/88) remained open pending fresh exact-head source checking and live publication gates. The earlier stream/empty-output source-check failures remain failures, not approvals. No subagent was started or revived. The authenticated read contract, accessible authorized inventory and private credential delivery remain separate blockers; public scripts establish none of them.

**Reconciliation finding and correction:** a new offline consumer regression reproduced an immutable-refresh MIME bypass: a fresh HTTP200 `text/html` response with identical script bytes incorrectly succeeded using the original JavaScript MIME and marked those original bytes revalidated. Fresh 200 script MIME/byte facts now use the same borrowed metadata validator before immutable comparison, still under the shared lease; original cached facts are validated separately on output. The regression passed green and retained unchanged original metadata; all thirteen focused SPOC cases passed. Actual corrected native offline reuse retained the original entry/script metadata and unchanged production governor bytes. No campus refresh was performed for this reproduction.

Corrected full source gate: **214 library + 19 CLI passes**, two ignored, five suites; strict all-target clippy and formatter check passed. The preceding 213+19 combined gate predates this correction, and the 205+18 gate predates main reconciliation. These development runs are not trusted-CI status or independent approval; the separately recorded source and integration decisions follow.

**Verified source merge:** [PR88](https://github.com/cyjin-yl/buaa-cli/pull/88) exact corrected source `20a0d9a2941cf0cbecdbec2cec14260852b77e1f` merged as `c29a896d4ae385f37099dacbaf25ad7ae00e62eb`. A fresh stateless no-tool public-source check returned no concrete findings; both nondefect notes received responses, including correction of an inaccurate omitted-constant claim. [Source-check limits, note responses and explicit exact-head maintainer decision](https://github.com/cyjin-yl/buaa-cli/pull/88#issuecomment-5968049624) were recorded before merge. Main bound the supplied public sections to the source head; the checker had no independent checkout/SHA, runtime, cache, session, media or rights observation. Live admin/maintain/push permission, exact head, clean mergeability, unprotected main and inherited rulesets[] were checked. Status pending/count0 and check-runs0 mean absent checks, not green/trusted CI. No formal GitHub self-approval, authenticated contract, transaction or account-safety relaxation is inferred.

**Actual merged runtime:** the first post-merge Git fetch failed with TLS termination and REST GET with EOF. Those failures remain recorded; no TLS disable or proxy fallback. Root first fast-forwarded to the locally available reviewed source and built offline. One later deliberate fetch/REST succeeded after that build interval; root fast-forwarded only to the actual merge and rebuilt. Nine actual merged-root cache-only commands passed: script, root/entry/default surfaces, IC policy and notice-source metadata, help/schema/capabilities. Entry/script original MIME, hashes, bytes, timestamps and HTTP200 revalidation facts matched; selected-page counts were 1/1/default2, IC `published_at` was 2026-09-29 with 38 paragraphs, and 44 capabilities still reported SPOC blocked. Production governor bytes stayed unchanged at 60,000/900,000-ms policy with auth disarmed and no latch/pending outcome: zero campus requests, authentication or mutations. [Merged runtime receipt](https://github.com/cyjin-yl/buaa-cli/issues/87#issuecomment-5968147258) binds this proof. This completes bounded public-source integration, not authenticated course/material/subtitle retrieval or all-college history.

## 2026-10-17: announcement source-admission correction

PR94 / issue93 now separate source admission from downstream parsing throughout the inherited news/SCSE/IC/aviation paths. HTTP200, exact HTML MIME, bounded nonempty UTF-8 and active-base checks run once; layout, missing-board, unadvertised-ordinal and undeclared-article errors remain errors but admitted originals reach private cache persistence before the inner result is returned. Supplied history reuses the same byte/base admission without invented HTTP metadata. Shared ordinal selection rejects conflicting active destinations and unreviewed control/percent/backslash syntax; duplicate identical responsive destinations are allowed. This follows the existing mainline nested-result convention rather than weakening transport admission.

For inherited news/SCSE/IC consumers, this correction is specifically response admission, advertised-target selection and cache-result semantics, not an all-parser semantic rewrite. Their pre-existing first-slot/ambiguous-container and some inactive-metadata selection gaps are not claimed fixed here; generic news/SCSE article ownership and every legacy row/date grammar require separate bounded work. New unique heading/anchor/body and ambiguous-header handling in this PR are limited to the aviation adapter; Beijing owns the matching change in PR96. No broad no-findings claim is inferred for legacy parser semantics.

The earliest source-authority layer also includes the independently prepared directory producer repair: active-only identity text, inherited hidden-source attributes, exact HTML MIME/base admission and private retention of admitted layout failures. Existing source-text walkers move once to the common HTML module instead of establishing a second implementation. Aviation now binds each desktop row's unique heading to that same unique anchor, refuses multiple desktop headings/bodies rather than concatenating prose, and keeps ambiguous publication headers unknown. Synthetic parser and real-loopback consumer cases cover these failure boundaries; their execution result belongs to the exact-head PR receipt, not the historical totals below.

The new `Offline Rust` workflow fetches the declared toolchain and locked dependencies separately, then checks format/build/tests/clippy and native help/schema/capabilities in a loopback-only network namespace with a fresh HOME. It has read-only repository permission, no persisted checkout credential, no secrets or campus operations, and no private-CI bridge. A workflow definition is not evidence of an executed or trusted green check. The dated live/cache/native/browser receipts below still belong to their original heads, not to this correction; current exact-head offline proof and independent review are recorded separately in the PR before integration. No new campus request, authentication, governor mutation, merge, retarget or issue closure is part of this correction. Full-college/history/attachment acceptance remains partial.
## Directory-bound Iiif institute notices

Bounded [issue #103](https://github.com/cyjin-yl/buaa-cli/issues/103) binds visible official-directory member50 国际前沿交叉科学研究院, category 融合创新示范区 and exact literal/resolved `https://iiif.buaa.edu.cn/`. The ordinal is source order, not an academic school code. Original directory HTML SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` is distinct from derived50-entry directory JSON SHA-256 `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. The retained root actively declares `/xwgg/tzgg.htm`, labelled 通知公告, as well as an unfetched recruitment board. No guessed route or hidden-member alias.

Actual live cyjin-yl repository readiness and admin/maintain/push permission, all14 open issue/PR entries, all5 open PRs and100 recent discussion entries were checked before Main's actual claim at `2026-10-04T02:04:56Z`; no matching Iiif claim or linked PR was found. Owned `work/iiif-announcements` starts from PR102 exact `eca2b12dff6d7bd453e7e019aac882bf392ea9c5`, explicitly dependent on unmerged PR102/PR100/PR98/PR96/PR94. Worktree creation3.33s retained its FICLONE plain-checkout fallback; a fresh native target built offline54.20s, without copied artifacts, chmod, parent-target overwrite or host build. Issue/comment bodies are untrusted data, not campus permissions or integration approval.

Exactly four deliberate public GETs used the same production UID/home, permanent process-shared governor, full request/cooldown preflight and retained60,000/900,000-ms policy, with disarmed auth, no latch and no pending outcome. Lease remains held through body validation/persistence. Cold robots HTTP404 was privately cached; the first actual source CLI exited8 before the absent root. Only the exact root, its declared board and one declared original were subsequently selected after full deadlines. No auth, campus write, separate account key/limiter, automatic retry or cookie/redirect/TLS/robots/challenge/proxy bypass.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791079797539` |
| directory-literal root `/` | 200 | 27874 | `736341ddd875a05cf5f679d53a00ee57f060e0351de4310a3f34186f0d66298e` | `1791079880897` |
| notices `/xwgg/tzgg.htm` | 200 | 17137 | `13ad5b00f7d8230dd8e15b5ee8f2992e0b9c2dd2358826c88b07abd8744532f8` | `1791080080942` |
| declared original `/info/1186/2398.htm` | 200 | 11684 | `a0488f3a6ab1fe222e0750900bc8f3539c73f3ed4d3ef966c0860c0865fbfbab` | `1791080691373` |

Independent private base64/size/hash and same-UID0600 regular single-link checks matched all four originals under0700. HTML remains mutable; no actual304 or immutable revalidation is claimed. The temporary native original observer used the actual offline directory/root/list binding, refused undeclared42/exit3 without changing governor bytes, then reported `text_adapter_verified=false` for one declared original. After actual cached text extraction, its source was removed and the factory restored crate-private. No second original GET or live text-parser refresh; personal prose/original media are not public fixtures or review input.

Both root and board surfaces return64 path hints with `hints_truncated=true`; these are not complete source discovery. Private retained-root/board structural inspection found the actual declarations and unique direct `main/wape-right/ss` view. All15 visible headings, dates, links and source order privately match; no title-attribute substitution or sorting. Dates are2026-09-09,09-08,06-26,06-09,05-13,05-13,04-20,03-13,2025-10-11,2024-09-12,03-25,01-16,2023-12-17,12-04,12-03. Inclusive2026-09-08 through09 selects2. One direct `span` owns the date; absent, invalid or ambiguous spans remain null and cannot satisfy a date filter. Scoped `wape-right/pb_sys_common/p_no` advertises ordinal2 at `/xwgg/tzgg/1.htm`; no later page was fetched or inferred. Actual page2 offline/page3 refresh/recruitment category refusals are7/7/2, without GET or governor changes.

The original has one direct `main/kuaiXun/kuaiXun-con/form`, one `title/h3` heading, one direct header div with `[发表时间]：2026-09-09`, and one direct `single-content#vsb_content/v_news_content` body. Its heading, date and one nonempty ordered source paragraph privately match. It also contains one image and one unfollowed same-host `.htm` material link, zero tables/attachment hints; no image download, OCR or linked-material read. An initial inspection tried three unbracketed publication-label hypotheses and found none; constrained punctuation inspection identified the actual bracketed caption without repairing data or fetching again.

**Partial-text correction:** the initial cached native result said `full_text` despite an untranscribed source-body image. A synthetic consumer regression reproduced red101/29.18s. After image content was made explicit, one intermediate six-case run passed5/failed1 because an unobserved image-only-success expectation contradicted the existing nonempty-paragraph admission. That boundary was preserved, unreachable success code removed and pure-image/empty bodies remain unavailable, not fake OCR or empty success. Final six synthetic/loopback cases pass0/7.32s; the original partial-text regression passes. Corrected native build0/10.42s and actual cached article0 now report `partial_text`, with original heading/date/ordered text/retrieval unchanged and no new GET. Cases defend row order/unknown-date filters, heading/view ambiguity, scoped ordinal selection, original header/body context, missing/invalid/ambiguous publication and image completeness, plus declared-only selected-page refresh and offline original reuse.

Actual native cached original exits0. Undeclared refresh/source_page3 refresh/source_page2 offline/noncanonical/off-host-with-source-page refuse3/7/7/2/2 before GET. All cache-only/refusal paths retain governor SHA-256 `fab6025a84db0fb84accda1c867989c076fa4a16a5afa44d0e8da7a6539a77cb`. Initial metadata checks had one script-only direct `sha256` KeyError; corrected to actual `response_body_sha256`/`response_body_byte_length`, reusing completed commands rather than reexecuting them. A structural inspector initially included one nonpersonal source-title attribute in tool history; subsequent inspection uses structural attribute allowlists, does not reprint/republish it, and does not claim zero original headings in private history. No raw personal prose is published in source evidence.

Scope: one current institute notice board and one declared original, with untranscribed/linked content explicitly missing. No recruitment-board/later-page live read, pure-image text support, all-college/faculty completion, complete history/archive extraction, linked-material or other-attachment retrieval/OCR, publisher/security/rights certificate, authenticated service or recording/Life claim. Shared1,024-paragraph/8KiB/2MiB budgets, governor and legitimate owner-controlled campus-write scope stay unchanged; current campus-write intent is none and assignment submission belongs to the owner. Full quality gate, local UI/source checking and exact-head external publication/integration are recorded separately, not inferred from focused proof. Parent/child independent exact-head approval and explicit maintainer source-contract decisions remain separate; aggregate announcements stays partial.

The coherent locked offline source gate passed **244 library + 19 CLI tests**, two ignored, five suites; strict all-target clippy and formatter check passed. Separately measured formatter1.63s/build16.48s/fulltest75.55s including lib64.73s/clippy22.13s/fmtcheck0.63s retain command boundaries. Earlier focused6-case7.32s and intermediate native builds are not extra full-suite runs. Prior Zfai238/H3i232/Shenyuan228/Beijing224/aviation220 plus19CLI retain prior source-head scope. Metadata/native/local-UI proof, fresh public-source checking and exact-head publication/integration remain separate; no platform approval, trusted/privateCI or deployed/root-main/Pages coverage is inferred.

After244+19 quality metadata, a separately measured6.82s offline native build preceded eight actual cache-only commands, all exit0: Iiif root/board/list/filter/article, help/schema/capabilities. Counts15/2/1 and all source rows/date filters/partial-text original facts privately remain equal; the44-capability output consumes244+19 metadata and keeps announcements partial. Governor bytes stay unchanged, no new GET or extra full-suite run. Unaffected legacy original receipts retain their exact-parent scope instead of being redundantly replayed; no legacy body/date contract was changed. Native schema output is not independent full-validator certification.

Actual local Chromium desktop1365x900/mobile390x844 observations and direct-helper WebP screenshots confirm the Iiif example, date filter,15/2/1 and partial-text/image/linked-content bounds,64-hint truncation, unmerged102/100/98/96/94 dependencies, current244+19 and prior238/232/228/224/220 labels. Fresh evidence-link clicks reach `#evidence` within1px of viewport top; document widths1365/390, scripts/external styles/frames/broken fragments0 and mobile code has a local scroller. Four captures were exclusively copied/fsynced0600 same-UID regular singlelink under private0700 outside source/tmp, with an exact observed HTML copy. HTML SHA-256 `b2e6574225275c7268ebec7f9f2a1c7294400e17661eb46daec4bdcb59770b05`; local proof, not Pages deployment. Tabs released/server stopped.

One fresh stateless no-tool check received15 complete public Rust files,481,373 prompt characters, Main-bound to initial committed source `99622b364d1727c31c7d351d9a378d93c220118d`. It reported two findings, not platform approval. The major cache-loss claim was rejected with precise type/control-flow evidence: Iiif wraps `normalize(...).map(...)` in outer `Ok`, making parser errors the inner `T=Result<Value,Error>`; the transport unwraps only outer `Ok`, persists validated cacheable bytes, then the source unwraps the inner error. Robots denial similarly uses `Ok(robots_decision(...))`. Existing IC layout-retention and robots-denial consumer tests actually passed in10.32s/0.76s; no separate native cold-IIIF-layout experiment is claimed. Persisting before caller response validation as recommended would weaken cache admission, so cache/governor policy was not changed.

The minor incomplete CLI-guidance finding was accepted: actual unmatched subcommand exit3 omitted `document`/`college-source`; corrected actual native output still exits3 and lists the supported command families. No wording-pinning test was added. Renewed coherent locked offline gate after this message-only Rust correction passes244library+19CLI,2ignored,5suites, strict all-target clippy and formatter check. Separately measured formatter1.21s/build0.25s/fulltest67.31s including lib63.78s/clippy3.20s/fmtcheck0.47s keep boundaries; the original75.55s/full244+19 receipt remains initial99622 scope. No new campus GET or original/body/date/cache/safety change. Fresh renewed source checking and exact-head publication/integration remain separate; a no-tool check does not independently observe checkout/SHA/runtime/private originals/permissions/rights/CI or supply approval.

The renewed fresh stateless no-tool check received the same15 complete public Rust files,481,747 prompt characters, Main-bound to `d42b96564a755a464540624b47655a2209ef0855`, and returned `no_concrete_findings`/empty findings. It explicitly confirmed the nested-Result cache reasoning. All14 Rust files other than `main.rs` are byte-identical to initial99622; the only Rust correction is static CLI guidance. Governor/organizations/all reviewed college modules and separate SCSE viewer/html helpers were supplied; docs/acceptance, integration-test files, external crates and unlisted dependencies were not. It independently observed no checkout/SHA/runtime/private originals/cache/permissions/rights/CI and supplies no formal approval. Both handles are completed; no duplicate wait/check is pending.

After renewed quality/finding metadata, a separately measured1.69s native build and actual cache-only capabilities/article commands exited0; renewed decisions are consumed by capabilities and the entire partial-text original/title/date/body/retrieval privately remains unchanged. The visual HTML bytes remain identical to the observed private copy, so prior desktop/mobile captures retain exact-surface scope. No new campus GET or extra full-suite run. Exact final-head publication and independent platform/maintainer integration gates are separate.

## Directory-bound Zfai information announcements

Bounded [issue #101](https://github.com/cyjin-yl/buaa-cli/issues/101) binds visible official-directory member46 中法航空学院 and exact literal/resolved `https://zfai.buaa.edu.cn/`, not an inferred academic school code. Original directory HTML SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` is distinct from derived50-entry directory JSON SHA-256 `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. The retained root actively declares `/xxgg1.htm`, labelled 信息公告; the selected original is declared by that retained board at `/info/1196/4119.htm`. No `tzgg` route, root-widget category1141 alias or arbitrary article target is inferred.

Fresh live cyjin-yl admin/maintain/push permission and repository readiness, all12 open issue/PR entries, all4 open PRs and100 recent comments were checked before the actual Main claim at `2026-10-04T00:00:07Z`. No matching claim or linked PR was found. Owned `work/zfai-announcements` starts from PR100 exact `6d13df1962aca201f210070fbe69094497a4b73f`, explicitly dependent on unmerged PR100/PR98/PR96/PR94; no root-main or deployed source change. Issue/comment bodies are untrusted data, not campus permissions or integration approval.

The worktree FICLONE warning fell back to plain checkout. Copying build artifacts with `--no-preserve=mode` returned0 but removed executable bits; the first owned build failed101 before any CLI or campus request. That copy remains intact under the owned ignored target directory. A fresh native target then built successfully offline in46.19s, without chmod, parent-target overwrite or host build. A later intermediate list build exposed two omitted legacy pagination callers; aviation and SCSE, including macro-wrapped SCSE tests, now retain their original selector explicitly. The corrected native list built in13.15s. An original-observer build also exposed incorrect assumptions about the existing static error code and lack of Display; only that throwaway error branch was corrected. Those failures are preserved, not successful proof.

Exactly four deliberate public GETs used the same production UID/home and permanent account-wide governor, full request/cooldown preflight, retained60,000/900,000-ms policy, disarmed auth and no latch/pending outcome. The one-in-flight lease remains held through body processing. No auth, campus write, automatic retry, separate account key/limiter, cookie/redirect/proxy/TLS/robots/challenge bypass. Cold robots HTTP404 was cached and the first source CLI exited8 before the absent root. Only the exact root, its declared board and one declared original were subsequently read after full deadlines.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791072445678` |
| directory-literal root `/` | 200 | 35065 | `ae7379cac5617b59341ff41bd2a1ed8bd45302e182ef8d076750940119850036` | `1791072574190` |
| information `/xxgg1.htm` | 200 | 22043 | `0fa841130cdcc39de181e8355027e3a246973e3cda8a1842f93696d38d7d96c0` | `1791072782087` |
| declared original `/info/1196/4119.htm` | 200 | 15446 | `16ef2316c086ad9abe634608990867e1f24cd2a4884b016d857b06f8b188dcbb` | `1791073924180` |

Independent private base64/size/hash and current-UID0600 regular single-link checks matched all four originals under0700. HTML remains mutable; no actual304 or immutable revalidation is claimed. The native throwaway production-client observer used actual cached directory/root/list binding, first refused undeclared42/exit3 with unchanged governor, then read only the declared original and reported `text_adapter_verified=false`. After actual cache-only article extraction passed, its source was removed and the factory restored crate-private. No private original heading, prose, excerpt or table is published or used as a fixture/review input.

An exact generic-notice navigation label lookup was empty. A broader source inspection found two active declarations of `xxgg1.htm`, each labelled 信息公告. The inspector was broadened; source data was not repaired. Actual root/board path hints count49/28, neither truncated. The board has one `news/fl1/list11` view and nine direct rows. All native headings, `rr/p.ps3` excerpts, links, dates and source order privately match. Source dates are2026-09-14,2026-09-12,2026-06-05,2025-06-27,2025-06-23,2025-06-20,2025-06-16,2025-06-12,2025-06-01; the inclusive2026-09-12 through14 filter selects two. Excerpts remain distinct from original article text.

The real board has `pagebar`, not `pb_sys_common`. Shared ordinal parsing now receives the reviewed selector from its caller, with all university/SCSE/IC/aviation/Beijing/Shenyuan callers retaining their original `pb_sys_common` selector. Zfai selects only `pagebar span.p_no` declarations: ordinal2 is `/xxgg1/2.htm`, ordinal3 is `/xxgg1/1.htm`. Neither later page was fetched live. Page2 defaults to offline miss7; unadvertised page4 `--refresh` refuses7 without GET, and invented category`tzgg` refuses2. No filename-number inference or automatic traversal.

The declared original has one direct `detail/fl1/wp/left/form`, one `ar_tit/h3` heading and one `ar_article/vsb_content_1001/v_news_content` body. Its original heading privately matches the listing; publication is the second direct header span's `时间：2026-09-14`, never the first click script or another/body date. All five nonempty ordered paragraphs privately match; the observed original has zero tables and zero attachment hints. Missing/invalid dates stay null; ambiguous headings/bodies fail closed while retaining original bytes.

Actual native cached article exits0. Undeclared original refresh/unadvertised source_page4/source_page2 offline/noncanonical/off-host-with-source-page refuse3/7/7/2/2. All cache-only/refusal commands preserve production governor SHA-256 `41f3d1799ef6f4c0e2ccd991783526592d8234638fd8ba71931c1e02e1e50444`; no campus GET followed the original observation. Four synthetic parser cases and one real-loopback case passed in a separately measured23.05s including compilation, covering excerpt/title separation, date/filter/source order, scoped ordinal declarations, original header/table/publication precedence, missing dates/ambiguity and selected-only declared refresh/offline original reuse. Fixtures are synthetic/sanitized; production governor bytes remain unchanged.

The coherent locked offline source gate passed **237 library + 19 CLI tests**, two ignored, five suites; strict all-target clippy and formatter check passed. Separately measured formatter1.16s/build13.52s/fulltest75.58s including lib63.81s/clippy18.69s/fmtcheck0.52s retain command boundaries. The earlier focused5-case23.05s and intermediate builds are not extra full-suite receipts. Prior H3i232+19/Shenyuan228+19/Beijing224+19/aviation220+19 remain prior-head evidence. Fresh source checking, metadata/native/local-UI proof and exact-head publication/integration are separate; no formal approval, trusted/privateCI or root-main/Pages deployment is inferred.

After237+19 metadata, a separately measured2.96s offline build preceded fifteen actual cache-only native commands, all exit0: Zfai root/board/list/filter/article; all seven existing Beijing/IC/aviation/news/SCSE/Shenyuan/H3i articles; help/schema/capabilities. Counts9/2/5 and all legacy original hashes, headings, dates, ordered body/results, byte counts and timestamps privately match; SCSE remains `embedded_document`. The44-capability output keeps announcements partial. No extra full-suite run or campus request; governor bytes remain unchanged. Native JSON schema output is not independent full-validator certification.

Actual local Chromium desktop1365x900/mobile390x844 observations and direct-helper screenshots confirmed the Zfai source example,9/2/5 bounds, title/excerpt separation, exact `xxgg1`/category1196/second-publication-span/`vsb_content_1001`, pagebar ordinal2/filename2 and ordinal3/filename1, current237+19/prior232+19/228+19/224+19/220+19 labels and unmerged PR100/PR98/PR96/PR94. Fresh observed evidence-link clicks reach `#evidence` within1px of viewport top. Document widths1365/390, scripts/external styles/frames/broken fragments0; mobile code has a local horizontal scroller. Four WebP captures were exclusively copied/fsynced under private0700 outside source/tmp with same-UID0600 regular single-link/hash checks. Tabs released/local server stopped. HTML SHA-256 `66eec51441e31444fb2f879e72983f316c4b878ca5b58b2f31ec8784caa8860f`; this is local proof, not Pages deployment.

**Concrete source finding and correction:** one stateless no-tool check of nine complete public Rust files bound by Main to the initial published source `9653040e98aa1c1befdd08ee534b5ce645d63924` reported ZF-AI-001: duplicate month-day or year slots silently selected the first date and could change filter membership. Main accepted it. A synthetic regression failed red with both ambiguous rows incorrectly dated2026-09-14, then passed green after requiring exactly one slot of each kind. Missing, invalid or ambiguous dates now stay null, retaining rows for unfiltered reads but excluding them from date filters. Actual corrected native list/filter/article still return9/2/5 with all retained headings, excerpts, dates, ordered body and retrieval facts privately unchanged; no new campus request or governor mutation. Checking scope is precise: complete `scse.rs` contains PDF admission and complete shared `announcements.rs` contains source HTML/text helpers, but the separately referenced `scse::viewer` declaration parser and `crate::html::script_kind` module were not supplied. Governor/organizations, the unmodified H3i module, docs/acceptance and private originals/cache were also not supplied; no independent checkout, runtime, permissions or platform approval was observed.

Corrected coherent locked offline gate: **238 library + 19 CLI passes**, two ignored, five suites, strict all-target clippy and formatter check. Separately measured formatter0.79s/build6.00s/fulltest87.84s including lib76.46s/clippy5.46s/fmtcheck0.65s retain command boundaries. All six focused source cases passed in separately measured0.70s. The previous237+19 gate, initial15-command/native/UI receipts and pushed965 source remain prior-head evidence, not renewed exact-head approval. Fresh corrected-head source checking and publication/integration remain separate.

After corrected238+19 metadata, a separately measured7.36s offline build preceded eight actual cache-only commands, all exit0: Zfai root/board/list/filter/article, help/schema/capabilities. Original list/excerpts/date/filter and full article/retrieval facts privately remain equal at9/2/5; governor bytes unchanged and no new campus request. Seven unaffected legacy article receipts remain initial965 scope rather than being redundantly replayed for a Zfai date-only correction.

Renewed actual local Chromium desktop1365x900/mobile390x844 observations/direct-helper screenshots confirm the ambiguous-slot null/date-filter wording, current238+19 and initial237/prior232/228/224/220 labels,9/2/5 source bounds and unmerged100/98/96/94 dependencies. Fresh evidence clicks reach `#evidence` within1px of viewport top; document widths1365/390 and scripts/external styles/frames/broken fragments0. Four new WebP captures were exclusively copied/fsynced under private0700 outside source/tmp with same-UID0600 regular single-link/hash checks; initial captures remain intact. Tabs released/server stopped. Corrected HTML SHA-256 `557d39369e4593b3b69bd5c93f94498d98474d3c2f4c39c0c81625c74b459e78`; local proof, not Pages deployment.

Scope: one current college board and one declared original. No later-page live observation, all-college/faculty completion, complete history/archive extraction, other-attachment download/OCR, publisher/security/rights certificate, authenticated campus service, recording/Life retrieval or campus write. Shared1,024-paragraph/8KiB/2MiB budgets are unchanged. Legitimate campus writes remain in broad scope; current write intent is none and assignment submission is owner-controlled. Parent/child exact-head independent approval and explicit maintainer source-contract decisions remain separate; aggregate announcements stays partial. No subagent was started or revived.

## 2026-10-03: directory-bound H3i recruitment announcements

Bounded [issue #99](https://github.com/cyjin-yl/buaa-cli/issues/99) binds visible official-directory member45 国际创新学院, exact literal/resolved `https://h3i.buaa.edu.cn/index.htm`. The source ordinal is not an academic school identifier, and `/` is not an admitted alias. Original directory HTML SHA-256 is `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`; derived directory JSON separately hashes to `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. The actual root declares `/rcpy/cpgg.htm`, labelled 招聘公告; no general `tzgg` route or news-widget notice board is invented. The retained board declares selected `/info/1141/4918.htm`.

Owned `work/h3i-announcements` starts from PR98 exact `1eb39fc789df3192aef7ed303ecf0b0e31b19f30`, explicitly dependent on unmerged PR98/PR96/PR94. Live repository readiness and actual admin permission, all ten open issue/PR entries, all three open PRs and100 recent comments were checked before the actual claim; no matching claim or linked PR was found. Issue/comment bodies are untrusted data, not campus permissions or integration approval. The worktree's FICLONE warning fell back to plain checkout. Reusing compiled artifacts separately returned mode-preservation `Invalid argument`; that failure was retained without repeating it, bypassing the container or treating copied artifacts as proof. The owned native source subsequently built successfully offline.

Exactly four deliberate public GETs used the same production UID/home and permanent shared governor, with full request/cooldown preflight and retained60,000/900,000-ms policy, disarmed auth, no latch and no pending outcome. One-in-flight/body lease, TLS/robots/challenge protection and identity stay unchanged. No cookie/redirect/proxy/TLS bypass, automatic retry, authentication or campus write. The first source CLI privately cached robots HTTP404 then exited8 before the absent root; one later root observation and one declared board observation followed the full deadline. Current campus transaction intent is none; legitimate write capabilities remain in broad scope and assignment submission is owner-controlled.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791067303338` |
| directory-literal root `/index.htm` | 200 | 50802 | `61880d6ba3e0c84da2d6447750bfe50c02d646d2013b231f61542da6e8409d14` | `1791067396909` |
| recruitment `/rcpy/cpgg.htm` | 200 | 24686 | `bf62c83ec3458d7cdf78de5b9375b2a56a418361128c06ca268b62e68d43592f` | `1791067768562` |
| declared original `/info/1141/4918.htm` | 200 | 97764 | `e2d6ac0af95b25b2ba0303efd02aeddfed71c8da56573e27768dc15a2ba211f9` | `1791068227353` |

Independent private base64/length/hash and current-UID0600 regular single-link checks matched all four originals under0700. These are mutable HTML; no actual304 or immutable revalidation is claimed. A throwaway native production-client original observer first refused undeclared42/exit3 without governor mutation, then fetched only the declared original and returned retrieval facts with `text_adapter_verified=false`. It used the actual cached directory/root/list binding and existing governor. After actual cache-only article extraction succeeded, the observer source was removed and its factory restored crate-private. No raw originals, personal headings/prose/table or source configuration enter public fixtures or review inputs.

Initial exact generic-notice label inspection found no match. A broader source inspection found recruitment declarations; an overly specific expectation of two same-label anchors, then all anchors saying 公告, failed. Actual source has five active declarations to that same board with three generic navigation labels, two saying 招聘公告. The private inspector was corrected; no source data or functioning native parser was rewritten to fit the expectation.

Actual native cache-only listing returns nine `news/fl1/list11` rows, with direct `rr/h4s2` headings and no summaries. All headings, links and dates privately match. Source order remains2025-03-06,2025-02-28,2024-04-19,2026-10-01,2026-08-24,2026-07-15,2026-07-10,2026-06-18,2026-05-29, not an invented chronological sort. Date slots are `MM-DD` then `YYYY`; inclusive2026-08-24 through2026-10-01 selects two. The selected original's direct `ar_tit/h3` heading matches the listing heading; its second direct header span is `时间：2026-10-01`, not the first click-counter/script slot. All181 nonempty ordered `vsb_content_1043/v_news_content` paragraphs, including two tables, privately match native output. Missing/invalid date slots stay null; other spans, sidebar headings and body dates are not substitutes, and ambiguous headers/bodies fail.

Actual `article --refresh` for an undeclared canonical target and unreviewed source_page2 refuses3/7 before a GET; noncanonical and off-host/source-page input refuses2/2. The page2 listing refuses7 and an invented `tzgg` category refuses2. All cached/refusal commands and exhaustive proof preserve production governor SHA-256 `61f52e26c6c5c6475e30ab7b857178afdf26d86e40512a9fbad15302f2c214d7`. Root hints64/truncated and board hints51/nontruncated are bounded metadata, not complete source coverage. Page1 is the only reviewed page; no later-page declaration/live observation is claimed.

Three synthetic parser cases and one real-loopback case passed for source order/real month-day dates/unknown-date filtering and no summary promotion; original header/table scope and second publication-slot precedence with no other-span/body-date promotion; ambiguous headings/bodies; declared-only selected refresh, no discovery GETs, original heading rather than a distinct listing teaser and offline same-byte reuse. All exhaustive fixtures are synthetic/sanitized, never the private originals. Shared1,024 paragraph/8KiB paragraph/2MiB HTML limits and account policy are unchanged; no subagent started or revived.

Coherent locked offline build/full tests passed **232 library + 19 CLI tests**, two ignored, five suites, strict all-target clippy and formatter check. Separately measured formatter1.02s/build8.08s/fulltest79.68s including lib65.61s/clippy8.39s/fmtcheck0.57s retain command boundaries. Earlier focused4-case run19.41s and intermediate native builds are not extra full-suite receipts. Prior Shenyuan228+19/Beijing224+19/aviation220+19 remain prior-head scope. Fresh source checking, metadata/native/local-UI evidence and exact-head publication/integration remain separate; no independent approval, trusted/privateCI or root-main/Pages deployment is inferred.

After232+19 acceptance metadata was recorded, the owned CLI rebuilt offline in a separately measured4.62s. Fourteen actual cached commands exited0: H3i root/board/list/filter/article; all six existing Beijing/IC/aviation/news/SCSE/Shenyuan articles; help/schema/capabilities. Counts9/2/181 and all legacy original hashes, headings, dates, ordered body/results and retrieval times privately match prior receipts; SCSE remains `embedded_document`, not invented text. The44-capability output consumes232+19 and keeps announcements partial; schema/help expose H3i, not a full independent JSON-Schema validator certificate. An initial private compatibility runner supplied a retained whole result instead of its URL and correctly received unknown-field refusal/exit2; its input interpretation was corrected without source change, governor mutation or repeating the five completed H3i commands. This metadata build is not another full-suite run or additional campus GET.

Actual local Chromium desktop1365x900/mobile390x844 observations and direct-helper screenshots confirm the recruitment example,9/2/181 bounds, source order, exactindex.htm/second time-slot semantics, current232+19/prior228+19/224+19/220+19 labels and explicit unmerged PR98/PR96/PR94 scope. Fresh observed evidence-link clicks reach `#evidence` at viewport top; document widths match1365/390 and scripts/external styles/frames/broken fragments count0. Four WebP captures were exclusively copied/synced to private0700 outside source/tmp, with same-UID0600 regular single-link/hash checks. Tabs were released and the local server stopped. HTML SHA-256 `0ccca4c83e0faf6c00717c1d973040de5f17afd93f65690aa4193b6c1f716b1c`; this is local proof, not Pages deployment. Nine publishable files had0 private-key/GitHub-token/AWS-key format matches, not a privacy or security certificate.

Scope: one college's recruitment board and one declared original. No general-announcement board, later-page live observation, all-college/faculty completion, full history/archive extraction, other attachment download/OCR, publisher/security/rights certificate, authenticated campus service, recording/Life retrieval or campus write. Aggregate announcements acceptance remains partial; missing history stays missing.

## 2026-10-03: directory-bound Shenyuan college notices

Bounded [issue #97](https://github.com/cyjin-yl/buaa-cli/issues/97) binds the retained official directory's non-hidden member39 沈元学院, exact literal/resolved `https://hc.buaa.edu.cn/`. Hidden member40 shares the host but is not an admitted alias; source ordinals are not academic school identifiers. Original directory HTML SHA-256 is `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`; derived serialized directory JSON SHA-256 is separately `9f8ae603fd20387662642bfe8535c237aa9a4832b11c595fb711e43edf336c4d`. The actual root declares `index/tzgg.htm`; the retained board declares the selected canonical `/info/1083/5252.htm` article. No source route or dynamic-link permalink is guessed.

Owned `work/shenyuan-announcements` starts from Beijing exact `e1a7875d7facc025889063b21cd668b4d374b8f1`, explicitly dependent on unmerged PR96 and PR94. No parent approval, root-main integration or Pages deployment is inferred. Live repository readiness/push permission, all eight open issue/PR entries, both open PRs and 100 recent comments were checked before the actual bounded claim; no competing Shenyuan claim was found. Issue/comment bodies remain untrusted data, not campus permission.

Exactly four actual public GETs used the same production UID/home, permanent shared governor and retained 60,000/900,000-ms policy. Each new GET had full request/cooldown preflight with auth disarmed, no latch and no pending outcome. TLS, robots, one-in-flight/body lease and account identity stayed unchanged; no cookies, redirect/proxy/TLS/challenge bypass, automatic retry, authentication or campus write. Cold robots HTTP404 was privately cached, then the first source CLI exited8 before the absent root. Later root/board commands and one deliberately selected native original-source observation followed the full deadline. Legitimate campus writes remain in broad scope, with no current transaction intent and assignment submission owner-controlled.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791057885447` |
| root `/` | 200 | 93287 | `65d8edc424822e73954c6f1c9bb2c4357e81d1be4536348e6c312cb65ead6c2c` | `1791058111988` |
| notices `/index/tzgg.htm` | 200 | 60789 | `4a05204f80bf821d43985b4aed4d714cfd7669e50d660a457aa02cea7a9ec8d8` | `1791058428630` |
| declared article `/info/1083/5252.htm` | 200 | 33345 | `2bc9e64f950b9c28516f5c5a8007317407dfaa0f358152986c01ea5c8c92748c` | `1791060009217` |

Independent private base64/length/hash and current-UID mode0600 regular single-link checks matched all four originals under mode0700. All are mutable HTML; no actual 304 or immutable revalidation is claimed. The temporary original-source smoke used the production `ArchiveClient`, cached directory/root/list binding and the same governor, returned only retrieval facts with `text_adapter_verified=false`, then its example source was removed and factory visibility restored to crate-private. It is not a live article-text adapter proof or a second live article GET. No raw original, personal title/prose/table or authentication configuration is public evidence or a fixture.

Actual cache-only native listing returns twelve canonical `tab_a1/list_box_03s` rows, not additional alternate-view rows: dates 2026-09-29, 2026-09-18, 2026-09-17, three 2026-09-12, 2026-09-10, 2026-09-06, 2026-06-17, 2026-06-04, 2026-05-28 and 2026-05-18. Three dynamic JSP query links remain in the listing but are not fetched or converted to guessed `/info/` paths. An initial private inspection counted only nine static `info/` links and incorrectly expected nine rows; that assertion failure remains recorded. The inspector was corrected to all twelve primary rows, not the functioning parser. Every visible heading privately matched the native row; inclusive 2026-09-18 through 2026-09-29 selects two.

Actual native article reuse returns the original direct `nav01/h3` heading, first direct header-date span `2026-09-29`, and all seven ordered `vsb_content_2/v_news_content` paragraphs. The original heading differs from the listing teaser; this source discrepancy is preserved rather than repaired or used to overwrite the original. Empty subtitle markup is not another title; multiple nonempty headings/bodies refuse derived output. Missing/invalid publication slots stay null and nested body dates do not become metadata. Private independent paragraph comparison and original/listing hashes match; production governor bytes stay unchanged throughout all offline commands.

Actual undeclared canonical article, dynamic query article, off-host/source-page input and unadvertised page3 refuse with exits3/2/2/7 before a selected GET, preserving governor bytes. Root hints are56/nontruncated; board hints are64/truncated, not complete enumeration. Actual page2 is only an advertised source link, not a live observed later page.

Four focused offline cases passed: canonical/alternate views, split day/year-month real dates, unknown-date filtering and dynamic-link preservation; direct original heading/date/body/table scope and no body/other-span date promotion; ambiguous headings/bodies; real-loopback undeclared refusal, advertised page2 binding, selected-only refresh and original/offline reuse with a distinct listing teaser. Exhaustive fixtures are synthetic and sanitized, never the private originals. Shared 1,024 paragraph/8 KiB paragraph/2 MiB HTML bounds and existing account policy are unchanged; no subagent was started or revived.

The coherent owned-source gate passed locked offline build, **228 library + 19 CLI tests**, two ignored, five suites, strict all-target clippy and formatter check. Observed build25.16s, fulltest79.13s including lib66.93s, clippy21.81s and formatter-check0.57s are separately measured command durations. Prior Beijing224+19 and aviation220+19 receipts retain their original source heads. A bounded nine-public-file private-key/GitHub-token/AWS-key format scan counted0, not a privacy/security certificate. Fresh public-source checking and actual exact-head publication/integration remain separate; this is not trusted/privateCI, independent approval or root-main/Pages deployment.

After recording the228+19 metadata receipt, the owned CLI rebuilt offline in a separately measured2.49s. Thirteen actual cache-only commands exited0: Shenyuan root/board/list/filter/article; existing Beijing, IC, aviation, news and SCSE articles; help/schema/capabilities. Counts12/2/7 and all five legacy original hashes, headings, dates, ordered body and result types match their earlier receipts; SCSE still reports `embedded_document`, not invented plaintext. The actual44-capability output consumes228+19 and keeps announcements partial; command-schema JSON exposes the new source, not an independent validator certificate. An initial proof lookup used the wrong schema envelope; the retained actual `commands.announcements` output was inspected instead of repeating the command. Production governor bytes stay unchanged. This metadata-only rebuild is not another full suite or additional campus GET.

Actual local Chromium desktop1365x900/mobile390x844 observations and screenshots confirm the new example,12/7 bounds, preserved listing-teaser discrepancy, current228+19 and prior224+19/220+19 labels, unmerged PR96/PR94 scope and working evidence navigation. Document width matches both viewports; scripts/external styles/frames/broken fragments count0, with existing local code/table scrollers. A raw `tab.run`/Puppeteer screenshot timed out30s; no identical raw retry or false capture claim. The verified direct helper succeeded, and four WebP files were exclusively copied/synced to a private0700 directory outside source/tmp, independently checked0600/current-UID/regular/single-link with hashes. Tabs were released and the local server stopped. Local HTML SHA-256 `9597537121b9094df8d0fa63bff832c5a715ae29ec8b126cbebec03c0c48abb6`; this is local visual proof, not Pages deployment.

Scope: one college, one current board and one declared original. No later-page live observation, dynamic-link body retrieval, full history/archive extraction, all-college/faculty completion, other attachment download/OCR, publisher signature/security/rights certificate, authenticated campus service or recording/Life retrieval. Aggregate announcements acceptance remains partial.

## 2026-10-03: directory-bound Beijing college notices

Bounded [issue #95](https://github.com/cyjin-yl/buaa-cli/issues/95) binds retained official directory member41, non-hidden 北京学院, literal/resolved `https://beijing.buaa.edu.cn/`, directory SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`. Ordinal41 is not an academic school identifier. The actual root declares `xwdt/gggs.htm` in its source links; the notice board declares the selected `/info/1014/1188.htm` article. No route is guessed and no source JavaScript is executed.

Development is in the owned `work/beijing-announcements` worktree, explicitly stacked on aviation PR94 exact `d38441e82fa39f689cb7c9ea92c292e576eea6b7`. The parent is not merged or approved merely because this child proceeds; child source checking, publication/integration and runtime/Pages proof remain separate. No root-main or deployed Beijing capability is claimed here.

Exactly four actual public GETs used the same production UID/home and permanent shared governor, retained 60,000/900,000-ms policy, disarmed auth, no latch/pending outcome and full request/cooldown preflight. TLS stayed verified; no cookies, redirects, proxy, automatic retry, authentication or campus write. Cold robots HTTP404 was privately cached, then the first CLI exited8 before the absent root on the 60-second/30-second wait bounds. Later deliberately selected reads followed the full global gap. Legitimate campus write capabilities remain in broad scope; no current transaction intent exists and assignment submission is owner-controlled.

| selected original | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| robots `/robots.txt` | 404 | 1693 | `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407` | `1791051384132` |
| root `/` | 200 | 46071 | `81ed48c09183e073039b0b08a4801f8cfb28b63794897b8754ec5539605b002f` | `1791051615557` |
| notices `/xwdt/gggs.htm` | 200 | 19680 | `5e80e54ae1eda74068fe58ec56dfca36bc6fbd1a847974c3c4b33ab5d90a7503` | `1791051991093` |
| declared article `/info/1014/1188.htm` | 200 | 437099 | `33f1588c5d183fca89893ab6063a486fc99b4ae904156a663ec40ff8ad93f0f8` | `1791052711871` |

Independent private-cache base64/length/hash and current-UID mode0600 regular single-link checks matched each original under a mode0700 cache directory. All originals are mutable HTML (`immutable=false`); no actual 304 or immutable revalidation claim. Personal article/table contents, original bytes and titles are not copied into public fixtures or review input; structural/retrieval facts and synthetic data are public proof.

Actual native cached listing returns three rows dated 2026-09-22, 2026-09-22 and 2026-09-08; the inclusive first-date filter returns two. Summaries are omitted. Unadvertised page2 exits7, undeclared own-site article exits3 and off-host/source-page input exits2 before a selected request, preserving production governor bytes. Root source hints are capped at64 with `hints_truncated=true`, not complete source enumeration.

The first article GET retained typed original HTML but returned unavailable with the shared 512-paragraph ceiling; it was not called a successful article adapter. An independent in-process private parse counted one `art-main`, one body, three tables and 795 nonempty source paragraphs. Source title/date binding comes from the direct `art-tit/h3` and `日期：...年...月...日` header, not the sidebar or body. The corrected actual native cache-only command returns the matching header/listing title, publication 2026-09-22 and all795 paragraphs, with original source/list hashes and byte-unchanged production governor. No second live article GET was needed.

The shared paragraph budget is now1,024, without a URL/source-specific exception; 2 MiB HTML and 8 KiB per-paragraph limits remain. A synthetic 1,024-paragraph table consumer reproduced the old rejection red; it now preserves every ordered cell paragraph, while1,025 fails unavailable rather than truncating. Three focused parser cases and one real-loopback transport case passed: dot dates/invalid dates/filtering; direct header/scoped table body and no body-date promotion; long-table boundary; source-advertised binding, undeclared refusal, selected-only refresh and private offline reuse. No campus traffic occurred during exhaustive proof.

Final coherent owned-source gate passed: locked offline build, **224 library + 19 CLI tests**, two ignored, five suites; strict all-target clippy and formatter check. This is not trusted/private CI, independent approval or deployed/root-main proof. The inherited aviation 220+19 and other dated receipts retain their prior-head scope. No subagent was started or revived; a stateless no-tool source check and actual exact-head integration gates remain separate.

After recording the 224+19 metadata receipt, the owned CLI rebuilt offline and thirteen actual cache-only paths exited0: Beijing root/notice sources, listing/date filter/article; IC, aviation and news articles; legacy SCSE root and embedded-document article; help, schema and capabilities. Counts remain3/2/795 and38/15/26; SCSE remains `embedded_document`, not invented plaintext. The 44-capability manifest consumes the new receipt and keeps announcements partial. Production governor bytes stay unchanged. This metadata rebuild is not another full-suite run; an earlier5.55-second metric included rebuild plus13commands, not a separately measured rebuild duration.

Actual local Chromium desktop1365x900/mobile390x844 inspection and screenshots confirm the Beijing example, shared 1,024 bound, 224+19 and prior aviation220+19 labels, explicit unmerged-stack limit and working evidence navigation. Document width equals both viewports; existing code/table auto-scrollers remain local. Scripts/external styles/frames/broken fragments count0. Tabs were released and the local server stopped; this is not Pages deployment. A bounded nine-public-file private-key/GitHub-token/AWS-key format scan counted0, not a privacy/security certificate. Personal originals/prose remain private; no additional campus GET, authentication or write occurred.

Scope: one college, one current notice board and one source-declared original. No later-page live observation, full history/archive replay, all-college/faculty completion, other attachment download/OCR, publisher signature/security certificate, authenticated campus service or recording/Life retrieval. Source checking and exact-head integration decisions must not be inferred from this local evidence.

## 2026-10-03: directory-bound aviation college notices

Bounded [issue #93](https://github.com/cyjin-yl/buaa-cli/issues/93) binds the official directory's non-hidden member7, 飞行学院, literal/resolved `https://aviation.buaa.edu.cn/`, source SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`. Ordinal7 is not an academic school identifier. Actual retained root declarations identify separate student notices `/xsgz1/tzgg.htm` and public notices `/gkgs.htm`; neither route was guessed. All source discovery is cache-first on the same private identity/governor, and only the selected target may refresh. Active base, untyped/wrong-MIME sources, off-host input, undeclared articles and unadvertised ordinals fail closed.

All five actual requests (robots, root, two boards and selected declared article) retained 60,000/900,000-ms policy, auth disarmed, no latch/pending outcome, full request/cooldown deadline checks, TLS validation and no cookies/redirects/proxy/retry. The first CLI cached robots HTTP 404 (1,693 bytes, SHA-256 `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407`, fetched `1791031419687`) then exited 8 before the root on the bounded-wait policy; its root cache was absent. Later deliberately selected observations followed full spacing. No authentication or campus write occurred; legitimate write capabilities remain in scope, with no current transaction intent and assignment submission owner-controlled.

| selected source | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| root `/` | 200 | 60186 | `e5da1ed83c3923f6666321b158b1716ac8f6eec76ee5d21feb2625581f19d809` | `1791031681215` |
| student notices `/xsgz1/tzgg.htm` | 200 | 32179 | `1a0f89b656f45a930abe5c267a329be39b49592a020517eef639204822c51bab` | `1791032300527` |
| public notices `/gkgs.htm` | 200 | 27297 | `1e6ba65da36d3517ba0300cd94c97785c2a553c9a23a8e06f83935242a7d3ffc` | `1791032899514` |
| declared article `/info/1061/2793.htm` | 200 | 61976 | `94783b96fc0d489fb069c9687b97f1fed9a6e04c4f3fb53911f0379362b2a132` | `1791033900366` |

Independent private-cache base64/length/hash checks matched each original. The public-notice summary contains personal information; no original/summary/prose is copied to public fixtures or review input, and no linked share/contact/external resource is followed. Public receipts use only title-independent structural and retrieval facts. Actual final article parsing is separately exercised from those retained bytes, not presented as a second live article request or a live text-parser refresh.

Actual native cache-only lists return four student rows and one public row, excluding their duplicated mobile presentation. Student dates are 2025-04-03, 2024-05-06, 2024-04-25 and 2024-04-16; all four original WeChat links remain un-fetched. Source spans are **day then slash-month**, not month/day; the single-date filter returns one row. The bound own-site article returns the source title, 2026-09-22 and 15 desktop `v_news_content` paragraphs, not 30 responsive copies. Undeclared same-shape article input exits 3, an unadvertised page 2 exits 7, and off-host article input exits 2 before a target request. All offline cases retain byte-identical production governor state; existing IC 38/news-center 26 paragraphs and dates are preserved after the shared extractor accepts an explicit DOM scope.

Four focused synthetic/loopback cases passed for ambiguous day/month, invalid-date filtering, responsive-row/prose exclusion, advertised source-page binding, undeclared refusal and selected-only refresh/offline reuse. A consumer regression first failed because a body date was promoted to publication metadata when the real header was absent; publication parsing now accepts only direct desktop-form date headers, and the regression passes with the date null. Layout-admitted originals stay private on article layout errors, which remain errors rather than generic success. Full source gate, fresh source check and exact-head publication/integration decisions are recorded separately; no merge or independent approval is asserted here.

Final corrected owned source gate passed: locked offline build, **220 library + 19 CLI tests**, two ignored, five suites; strict all-target clippy and formatter check. This development run is not a signed private-CI status or independent approval. Initial aviation candidate `97705de1bb68d327feac7a58fd906a60b7d8bf58` 218+19, body-corrected `70289cebfc469030439ebbf858e7eec4f5abcf0a` 219+19, earlier SPOC 214+19 and IC 205+18 receipts retain their prior-head scope.

At the initial candidate, after the metadata-only 218+19 receipt update, the actual owned CLI rebuilt offline and seven native paths passed: both lists, explicit source-page article, public-board source metadata, schema, help and capabilities. Counts remained 4/1/15, article date/hash/original retrieval time matched, the 218+19 receipt appeared in the still-partial capability, and production governor bytes stayed unchanged. This rebuild is not another full-suite run. Actual local Chromium desktop 1365x900/mobile 390x844 inspection confirmed the aviation row/examples, current/prior gate labels and evidence navigation; document width matched both viewports, with existing local table/code auto-scrollers. No executable scripts, external styles, frames or broken local fragments were found. Ten bounded public-file private-key/GitHub-token/AWS-key format scans had zero hits, not a comprehensive privacy/security certificate. Those managed tabs and smoke server were closed.

The initial head's slow stateless source check returned no structured response; that failure is not approval or no findings. A distinct default-route no-tool excerpt check returned **F1**: IC's migrated root-scoped body call could combine multiple article bodies. Main reproduced the synthetic input red (two paragraphs incorrectly returned as full text) and corrected it green. IC now requires its single source `v_news_content` container; ambiguous bodies return unavailable rather than guessing a desktop selector from aviation. An independent in-process parse of the retained private IC original counted one body container and matched SHA-256 `b6b1353931f013d67ad424b30fd506cbb30f9212a540359442ac497ec914fa32`. Actual corrected native cache-only extraction preserved all 38 paragraphs, attachment output, source heading/date and hash with unchanged governor. This is an offline correction, not a new live IC observation. The changed head requires a fresh source check and its own publication/maintainer/integration gates; none is inherited from the initial candidate.

At the body-corrected `70289cebfc469030439ebbf858e7eec4f5abcf0a` candidate, after the 219+19 metadata receipt update, the owned CLI rebuilt offline and nine actual native paths passed: both aviation lists, aviation/IC/news articles, selected aviation public-board metadata, schema, help and capabilities. Counts were 4/1 and 15/38/26 paragraphs, with source dates, original cache hits/hashes and byte-unchanged production governor; the 44-capability output still marks announcements partial and consumes that 219+19 receipt. This metadata rebuild is not an extra full-suite run. Actual local Chromium desktop1365x900/mobile390x844 navigation and screenshots confirmed that gate, IC ambiguity boundary and prior-head labels, no document-width overflow, scripts, external styles, frames or broken fragments. The two managed tabs and smoke server were closed. This is prior-head local UI evidence, not deployed Pages proof.

That changed head's fresh no-tool excerpt check found a second **F1**, distinct from the initial body finding: IC admitted a matching resolved root without checking the literal directory href. The matching-resolved/nonliteral `/./` fixture reproduced incorrect admission red, then passed after moving the literal requirement into the shared college predicate and removing aviation's redundant local guard. The original unique/non-hidden/resolved identity and ambiguous-member refusal remain intact. Hidden/ambiguous fixtures now include valid literal roots instead of failing for a missing field. Seven IC and three aviation parser cases passed; four actual cache-only root/article commands still succeed with IC38/aviation15 paragraphs and byte-unchanged production governor. [PR94](https://github.com/cyjin-yl/buaa-cli/pull/94) was created at the body-corrected head; this further correction requires a new exact-head check and publication/gates. Its Copilot comment reports quota exhaustion, not approval; pending status/count0 and check-runs0 are not green CI.

After the final 220+19 metadata update, the owned CLI rebuilt offline and eleven native paths passed: the previous nine cache-only paths plus both IC/aviation root-source commands. Lists4/1, articles15/38/26, six original hashes/cache hits, partial capability status and production governor bytes stayed intact; the new 220+19 receipt was consumed. This rebuild is not another full-suite run. Actual local Chromium desktop1365x900/mobile390x844 evidence navigation/screenshots confirmed 220+19, the shared exact-literal/resolved admission boundary and dated 218/219 labels, with document width equal to each viewport and no scripts/external styles/frames/broken fragments. Tabs/server were closed. This is still local proof, not Pages deployment or changed-head approval.

Scope: one college, two selected current board pages and one declared own-site article. No later-page live observation, external WeChat body retrieval, aviation archive replay, complete history, faculty/all-college completion, other attachment download/OCR, rights-qualified recording/Life inventory or authenticated campus service. `announcements` acceptance remains partial; missing history is not reconstructed.

## 2026-10-03: directory-bound integrated-circuit college notices

Bounded [issue #89](https://github.com/cyjin-yl/buaa-cli/issues/89) implements the retained official directory's non-hidden member19, 集成电路科学与工程学院, exact `https://ic.buaa.edu.cn/`. Directory SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9` and retrieval facts accompany the separate college snapshot. Root must declare `/tzgg.htm`; selected articles must be declared by their retained notice page. Only reviewed root/robots/notices/numeric notice pages and `/info/1042/<id>.htm` are admissible. No guessed pages, JS execution, automatic crawl or followed attachment hints.

All actual source observations used the same account governor with retained 60,000/900,000-ms request/background policy, auth disarmed, no latch/pending outcome and full deadline checks. First source CLI cached robots HTTP404 (1,693 bytes, SHA-256 `29c0b0a5db57af93122bca27d4c301f5d1b7d34e5f410a85b4c1af2e747a1407`, fetched `1791005337235`) then exited8 before the root on 60-second/30-second bounded-wait policy. One preflight with 6,877ms residual refused locally before command execution. Later deliberate observations after the full deadline succeeded; no policy reset, alternate account key, automatic retry, cookie/login, challenge/TLS/robots bypass or campus mutation.

| selected source | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| root `/` | 200 | 154994 | `d331a57910da181e505cad199c15355baf37606aba7f186035c6905f4dfd8866` | `1791005451153` |
| notices `/tzgg.htm` | 200 | 20958 | `c5f95e8d45f0a9e13c0fc0b2125e4559211b36ebf7e668452af5cc32ca9e572e` | `1791005714328` |
| advertised page2 `/tzgg/22.htm` | 200 | 20992 | `45214f4141f2d553fac22e22b28fb80386c27604e7fce1971fdf4c97a5a37cb3` | `1791007660830` |
| declared policy `/info/1042/4815.htm` | 200 | 20338 | `b6b1353931f013d67ad424b30fd506cbb30f9212a540359442ac497ec914fa32` | `1791006484430` |

Both selected listings returned12 rows. Actual offline reuse matched root/list/article/page2 hashes and a date/title filter selected only the policy; an undeclared canonical article returned unsupported/exit3 without governor mutation. Original private HTML is separate from derived JSON paragraphs. Independent private base64/length/hash checks matched retained root/notice/article originals. The generic news-center article parser initially selected sidebar heading `通知公告` and no date, despite 38 paragraphs; this failure was not called valid article metadata. A retained regression failed red, then source-specific `ar_tit/h3` and `发布日期` parsing returned the correct policy title, 2026-09-29 and38 paragraphs from the same cached bytes with unchanged governor, no second article request. Paragraph/inert-script/attachment-hint behavior is shared, not a parallel parser convention.

Offline proof includes observed split-year/month-day dates with missing/invalid dates staying null, inert/foreign ordinal refusal, exact MIME/base admission, hidden/ambiguous directory refusal, source-bound selected-only loopback refresh and layout drift retaining typed originals while still returning an error offline. A wording-pinned help/schema test was deleted rather than re-pinned; source-page/credential-redaction CLI behavior replaces it. Full exact-head proof and independent review/maintainer/live integration gates remain separately tracked; no completed merge or source-review success is asserted here. No subagent was started or revived.

Scope remains **one college, two selected notice pages and one non-personal policy article**. No all-college/faculty completion, IC archive extraction, complete history, attachment download/OCR, publisher signature/external checksum, authenticated account service or rights-cleared recording/Life inventory. `announcements` acceptance remains partial. Valid original HTML on a parser-layout failure is retained privately for an offline correction; failure is never converted to a generic full-text success.

Review-corrected source gate: locked offline build/full tests **205 library+18CLI passes**, two ignored, five suites; strict all-target clippy and formatter check passed. The initial nine actual offline native commands passed for IC root/notices/list/page2/article and help/schema/capabilities plus legacy SCSE root/news-center article; after the common attachment fix, actual existing news retained26 paragraphs and IC policy38 with its title/date/hash and unchanged governor. Nine bounded public-file credential-format scans had0hits, not a comprehensive security verdict or independent source certification.

A stateless no-tool source check of initial exact head `33ad20f89c749dbaf651f859063d520abd0b242a` identified the shared attachment extractor's missing inert-context/label policy. This is source consistency evidence, not platform approval or runtime/SHA verification by that checker. Main's retained consumer regression reproduced script/style text leakage in labels red, then passed green. Template/noscript anchors were already omitted by this parser fixture, so that suggested leakage was not separately reproduced. The common extractor now excludes inert outer context and uses linear active-text labels without a second ancestor scan, preserving active image-only links. New corrected-head no-tool source check returned no concrete findings in supplied excerpts with explicit static/SHA/runtime/cache/omitted-helper limits; it does not inherit approval.

**Verified merge/runtime:** [PR90](https://github.com/cyjin-yl/buaa-cli/pull/90) exact corrected source `dca1fbff8e86dae700a9c7ba4eb6e27f027cf67e` merged as `516a4efc44960c0cd35c2957fde8d359f7526cb7` after [narrow source check/finding resolution and explicit maintainer decision](https://github.com/cyjin-yl/buaa-cli/pull/90#issuecomment-5966708966). Live admin/maintain/push permission, exact head, mergeable/clean, unprotected main and inherited rulesets[] were checked; status pending/count0 and check-runs0 are absence of checks, not green/trustedCI. No formal GitHub self-approval or inferred campus permission. Root fast-forwarded only, rebuilt actual merged CLI, then IC page2/list, bound policy article, directory/root-bound notice source and capabilities passed offline with same original hashes/date/38 paragraphs/cachehits and byte-unchanged governor. [Actual merged runtime receipt](https://github.com/cyjin-yl/buaa-cli/issues/89#issuecomment-5966775896). This is no extra full-suite run or live conditional refresh claim. Pages REST reported built exact516a4ef; deployment/browser proof is recorded separately, not assumed from that build. Other scopes remain missing.

## 2026-10-02: exact homepage archive replay and dated search

On actual merged main `f1da526ebfe4be5f90ad71cc9dacee7013c505ad`, `archive capture --online` first cached fresh archive robots HTTP 404 (146 bytes, SHA-256 `55f7d9e99b8e2d4e0e193b2f0275501e6d9c1ebd29cadbea6a0da48a8587e3e0`, fetched `1790942273506`), then exited 8 before the target on the retained 60-second/30-second wait bounds. This supersedes the old robots-network/boot blocker, not the historical failed observation.

After independently checking `pending=None`, no latch and the full shared deadline, one deliberate exact replay returned `capture_found`, HTTP 200 `text/html`, original `http://www.buaa.edu.cn:80/`, timestamp `19970416014726`. Memento date `Wed, 16 Apr 1997 01:47:26 GMT` and original Link matched. The 3,758 immutable bytes have SHA-256 `4cf418189fb99ac5cf2873673337b3722d7e42e60e38ad633ceb706e7c6fb05d`, fetched `1790944036626`. Independent base64 decode/size/hash verification and actual offline replay passed with the same identity and bytes. Publication date stays null/unknown; origin Date/Last-Modified are not publication proof.

A separate bounded exact-URL CDX date search for `https://www.buaa.edu.cn/`, inclusive 1997 bounds and limit 10, returned `19970416014726` and `19971210122410`: 327 response bytes, SHA-256 `7d942e8e87eb0864e73697d69b2f368e528343a56b12ec945e53a723573271cc`, fetched `1790944266753`. Actual offline replay matched hash/captures. `more_results=false` is only this index-page fact; `complete_history=false` and null CDX resource hashes remain explicit. No second resource fetch or all-college/history inference.

[Issue #82 operational evidence](https://github.com/cyjin-yl/buaa-cli/issues/82#issuecomment-5952491700) records the exact scope. No automatic retry, original-host fetch, closest-capture fallback, credentials, authentication, mutation, account-key split or governor-history reset. Historical failed-replay branch `2e4b7e45ab98243dae4eaae8f6638990832d0c1c` remains preserved. General TimeGate/TimeMap crawling, archived announcement extraction/college coverage and Life/transcript integration stay unfinished; this is a homepage proof, not complete historical content.

## 2026-09-20: initial offline iteration

The mounted workspace contained no project files or acceptance matrix. This iteration therefore creates original Rust source rather than claiming to resume an existing implementation. `acceptance.json` is the machine-readable scope and catalog-entry ledger. Pending means not implemented; links do not count as implemented APIs. The timed-input utility is the selected non-VPN feature. No campus request, authentication attempt, attendance action, enrolment, submission, ticket purchase or drive mutation is authorized or performed.

## Observed blockers

| Boundary | Attempted evidence | Consequence / resolution |
| --- | --- | --- |
| GitHub publication | An isolated private CLI profile resolved the initial preferences-file permission issue without copying or printing credential values. Authenticated owner/admin/push permission, empty initial branch state and repository rules were checked. | Initial source `26babf37a3e4f898af8988ad945e2af6aadfa9c4` was published after two independent exact-head source reviews, 50 offline tests, strict clippy/formatter checks and a 24-file bounded credential-format scan. This receipt update is tracked by [issue #1](https://github.com/cyjin-yl/buaa-cli/issues/1); normal PR/merge gates still apply. |
| skills-fs source | The reference mount is absent; both unauthenticated and authenticated requests for the authoritative repository returned 404. | Actual Go provider, mounting and stream contract remain unavailable here. Do not invent a compatible manifest. Public napcat-cli documentation is readable but is not a substitute for the authoritative Go contract. |
| Live campus service contracts | No owner-approved authenticated read observation has been performed; the only probes performed were the unauthenticated network-edge TLS probes recorded under Campus egress (2026-09-25). No credentials were used. | Live adapters remain pending or blocked until a reviewed contract and scoped read authorization exist. No real mutations are authorized. |
| Campus egress (2026-09-25) | Operator-authorized read-only gateway usage attempt plus diagnostic TLS probes on `gw.buaa.edu.cn`, `spoc.buaa.edu.cn` and `ihome.buaa.edu.cn`. All three: TCP connect OK, certificate verify OK, then TLS handshake severed at the network edge (`SSL_ERROR_SYSCALL` / `unexpected EOF`) with zero response bytes. Operator confirmed no login is possible from this devcontainer. | Egress block is domain-wide, not credential-specific. No live campus read, login, or mutation can be completed here. All live-verification acceptance items stay blocked until reachable `*.buaa.edu.cn` egress exists. No credential was transmitted. |
| SPOC materials/video | Acceptance links are historical community tools; no owner-reviewed service contract, authorized course inventory or rights-reviewed sample is available. No campus request was made. | No adapter/download/transcript claim. Await a scoped read authorization, exact service contract and rights-reviewed materials; never execute catalog scripts. Tracked by [issue #42](https://github.com/cyjin-yl/buaa-cli/issues/42). |
| Classroom live replay/audio repair | Only historical community-helper links are listed; no owner-reviewed current replay contract, authorized course inventory or rights-cleared original/derived sample is available. No campus service was contacted. | No endpoint, download or audio-repair adapter is claimed. Await scoped authorization and the service/materials contract; tracked by [issue #47](https://github.com/cyjin-yl/buaa-cli/issues/47). |
| Life catalog/storage | A safe catalog/evidence policy was reviewed, but no non-sensitive object-storage/retrieval contract is available. | Do not infer storage endpoints or copy private records/media. Life-specific retrieval remains blocked pending the owner's contract. |
| Crater | No real allocation/API/SSH contract available in supplied context or reviewed catalog. | Await reviewed service contract and owner authorization; no guessed endpoint. |
| Gitea CI bridge | No maintainer-approved bridge contract or exact-SHA permission available. | Proposal only; no privileged workflow, unsigned claim of verification, or untrusted PR checkout with secrets. |

Rust was absent from PATH. Installed official rustup minimal toolchain privately under `/home/ezra`, not on the host. Campus rate controls were not relaxed to resolve infrastructure issues. One public GitHub raw fetch had a TLS error; no certificate-validation bypass was used.

## Reviewed sources and license boundaries

- [awesome-buaa](https://github.com/buaahub/awesome-buaa): read every catalog entry, including struck-out historical references. `acceptance.json` maps every entry to acceptance scope. The credential-stealing `buaalzm/buaaGatewayAutoLogin` entry is explicitly excluded and its repository was not fetched or executed. No catalog program was run.
- [dhy2000/TimeInput README](https://github.com/dhy2000/TimeInput): documented `[seconds]text` input, realtime pipe output and EOF semantics. Implementation here is original Rust; no source or binary copied. Upstream warns not to submit its library/source as coursework.
- [fontlos/buaa-cli](https://github.com/fontlos/buaa-cli): MIT license text, README/tree and pinned command definitions reviewed. Password arguments, automatic check-in/evaluation and TLS-disable options are not adopted.
- [fontlos/buaa-api](https://github.com/fontlos/buaa-api): MIT license text and pinned request/context/SSO/gateway code reviewed. The inspected library default enables invalid-certificate acceptance, context construction probes campus reachability, SSO can automatically continue after a security notice, and gateway errors format raw responses. None of those behaviors is adopted. Service-specific live contracts remain unverified.
- [BUAASubnet/UBAA](https://github.com/BUAASubnet/UBAA): MIT license text, README/tree, server-route documentation and pinned authentication routes reviewed. Its JWT proxy API is distinct from native campus endpoints; client-side pacing cannot establish server-side account-wide governance. Service-specific campus contracts remain pending.
- [BUAASubnet/srun](https://github.com/BUAASubnet/srun): GPL-3.0 metadata. README reviewed as historical/protocol context only; no code copied into this MIT project. Do not adopt rapid retries, multi-dial or TLS verification skips.
- [cyjin-yl/napcat-cli](https://github.com/cyjin-yl/napcat-cli): read the integration README and inspected `napcat_cli/data/skills-fs.json`: dynamic directories, read/write API nodes, JSON/raw write parameters and an HTTP provider URL. Its README references historical `yandu-app/skills-fs` commit `cb13f37`; that is not proof of the current `skills-fs/skills-fs` contract. A referenced fragment URL returned 404. Authoritative Go mounting/provider/stream implementation remains blocked.
- [Proto-UI AGENTS.md](https://github.com/Proto-UI/Proto-UI/blob/main/AGENTS.md) and [contributor-agent governance](https://github.com/Proto-UI/Proto-UI/blob/main/internal/agent-operations/contributor-agents.md): reviewed authority/claim/review/exact-head principles. Their repository-specific permissions do not grant permissions here.
- [Detailed upstream assessment](REFERENCES.md) records exact inspected revisions, source-only proof, GPL/AGPL/LPPL boundaries, template/font caveats and the inaccessible authoritative skills-fs contract. It is not a live service/security exploit test or permission to execute catalog programs.

## Next work selection

The authoritative organization directory became the next priority after the archive transport was implemented. An owner-authorized bounded observation used the production shared governor; exact evidence is recorded below. Announcement parsing/crawling remains separate and pending.

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
- No campus requests, authentication attempts, or mutations occurred during this archive iteration. At that earlier checkpoint there had been no live Internet Archive observation. General Memento TimeGate/TimeMap crawling, college discovery, announcement extraction and Life/transcript integration remain separate pending capabilities.

Remaining proof limits at the original archive checkpoint: full devcontainer image build unavailable; production certificate/proxy behavior, socket teardown internals and every possible combined-signal/time-boundary case are not independently exercised by the offline suite. Namespace-isolated production CLI smoke was unavailable (`unshare` is denied), so the initial archive CLI checks stayed cache-only/invalid-input.

The archive checkpoint's bounded credential-format scan covered 22 explicit public source/document/manifest files with no matches; values were never printed. This is not a universal secret-detection guarantee. The project-owned working branch is `work/archive-provenance`; Git trust was scoped to individual commands for the owner-authorized workspace mount, not a global wildcard. Subsequent GitHub access recovery and repository creation are recorded above.

## 2026-09-24: archive resume-key projection repair

Issue [#21](https://github.com/cyjin-yl/buaa-cli/issues/21) matched Internet Archive's documented resumption-key behavior and its upstream [pagination-skip reproduction](https://github.com/internetarchive/wayback/issues/121). The CDX request now asks for `urlkey` first, validates it on every result row, and keeps it out of public capture JSON. The cursor remains server-generated, opaque, and passed through unchanged.

- `cargo build --locked --offline` succeeded in the project-owned `work/archive-resume-urlkey` worktree. Automated tests were not run for this follow-up; synthetic two-page and malformed-`urlkey` regression cases were added but remain unexecuted.
- Manual CLI observation 1: `buaa archive lookup --online` for `https://www.buaa.edu.cn/` with `limit=1` returned HTTP 200, capture `19970416014726`, `more_results=true`, and a next cursor. The request URL included `fl=urlkey,timestamp,original,mimetype,statuscode,digest,length`. Response-body SHA-256: `2872f76049005c06c6cc59415eced8d2f65119f0a85bc52ec65d1c3f80e18d19`.
- Manual CLI observation 2: the exact returned cursor was supplied unchanged in a second governed query; it returned HTTP 200, capture `19971210122410`, and another cursor. Response-body SHA-256: `71d84e325eb151c28ca6ca6c77e105ed23973356b7342a36396e93f4f79062ec`. The two response timestamps were 238,140 ms apart, above the shared governor's 5,000-ms minimum.
- Manual offline replay of page 1 returned `cache_status=hit` with the same response hash. Both public outputs omit `urlkey`; `more_results` remains true, so this proof does not claim complete history or absence of all possible gaps.
- An independent static review of current `main@6f0dcfbe597acfd698d433daeaa75037e0a3fdcd` found no remaining STR-ARCHIVE-001 source findings; the result is recorded on [issue #21](https://github.com/cyjin-yl/buaa-cli/issues/21#issuecomment-5807816941). Rust tests remain unexecuted for this review.

## Documentation landing page

`docs/index.html` is an original static, docs-first page with neutral surfaces, readable commands and explicit capability limits, without gradients or badge walls. After PR #43, GitHub Pages built `main:/docs` at `ce9243a5530d8a919dd3bee3ee7701de0cbaf0ab`; Chromium confirmed the deployed HTTPS title/H1 `buaa-cli`, updated archive evidence row, no external resources and no desktop horizontal overflow. On 2026-10-02, the latest pre-receipt build was `35e37edd2524785a1a6a88ce436ff64435a9d4f2`, built at `10:17:36Z`. Chromium confirmed the actual deployed title/H1, no external resources, desktop/mobile layout and working evidence-anchor navigation. The operational-receipt update corrects stale test/college/credit/governor claims; its actual local HTML was visually verified at 1365x900 and 390x844 with no document horizontal overflow. Deployment of that documentation-only head is verified separately after merge, not inferred from the earlier build.

## Initial verified marks/GPA offline iteration

Implemented `marks gpa` and `marks baseline save|show <absolute-path>` as a fully offline, policy-provenanced GPA engine. No campus grades are fetched: callers supply the published policy and course list. Baselines are atomically persisted at mode `0600` only beneath an existing current-user-owned, non-group/world-writable parent with no symlink path components; unsafe legacy files fail closed.

The structured diff binds to the baseline's **normalized policy content**, not only `policy.id`: an id is a label, and a baseline saved under the same id with a changed band/formula is rejected as `invalid_input` instead of re-scoring unchanged courses under a silently different scale. Both canonical (`gpa_baseline`) and raw policy shapes normalize to the same comparison form (table bands sorted by `min`, default `pass_min` applied), matching `PolicyContext::as_value`.

- `cargo test --locked --offline`: **51 passed**, one intentionally ignored subprocess worker (lib) plus 8 integration tests. Strict all-target clippy passed (zero warnings) and Rust formatter applied. Independent review found one blocker (stored `gpa_baseline` could not drive the diff because the strict course parser rejected derived `point`/`counts` fields), two majors (score over 100 accepted; top-level `error` input echoed into success output) and minors (unbounded formula `pass_min`, post-parse size check, non-atomic save, missing save provenance). All fixed with new regressions `saved_baseline_drives_diff_round_trip` and `score_over_100_and_error_echo_are_rejected`; re-inspected head `18b6a64`.
- Actual CLI proof: table-policy GPA of 3.6667 across weighted courses with a failing course excluded; idempotent baseline save (`saved` then `unchanged`); baseline show round-trip; relative baseline path rejected as `invalid_input` exit 2; missing/oversized policy rejected.
- The live campus grades adapter remains blocked: no authorized grade read or published grade-point table is available; no credentials were used. Status in `acceptance.json` is `partial-offline`, with the blocker recorded explicitly. No live adapter, fake endpoint, or generic success stub is present.
## 2026-09-24: GPA arithmetic and credit identity review fixes

The current branch implements offline fixes for #22 and #25: course and aggregate credits are bounded below the `round4` f64 scaling limit, baseline parsing applies the same bound, and output schema declares finite numeric aggregate fields. Baseline saves use descriptor-relative `0600` staging, file and directory synchronization, and atomic rename; existing files must be regular, private single-link files. A Linux CLI regression sets `umask 0022`, saves and changes a baseline, and observes mode `0600` each time. Unsafe parents, symlinks and non-regular targets fail before reporting `saved`.

The current branch implements offline fixes for #23 and #24 against the checked-in public school-8 course catalog: unknown majors reject before classification; the machine schema enum matches the catalog's non-general major tags; name-only duplicate selections reject when credit, displayed metadata or category/counting differs for that major. Identical duplicate rows remain a single selection with an explicit warning.

Final proof: `cargo test --locked --offline` passed **126 tests across five suites; one subprocess worker is intentionally ignored**. Strict all-target clippy, `cargo fmt --all -- --check`, and `cargo build --locked --offline` passed. The CLI mode test observes baseline create/unchanged/changed at `0600` under `umask 0022`; CLI credit tests reject the unsupported-major and conflicting-row cases. All inputs are synthetic and offline; no campus grades or other campus endpoints were accessed. The live marks adapter remains blocked pending authorized grade access and an exact published policy. Independent exact-head PR approval and maintainer merge approval remain required.

## Pinned Fengrubei template retrieval

Issue #9 bounds the feature to the upstream community release v1.0.3 at tag commit `20e27c67ebf09cc730d8988d7395d9a8d34acf47`. A one-time public observation used four separately governed requests (GitHub robots, fixed release URL, release-assets robots and validated asset redirect), at least five seconds after each completion. No campus endpoint, authentication, proxy, cookie, automatic redirect/retry or TLS bypass was used.

The observed release ZIP is exactly 52,816,733 bytes with SHA-256 `08b9ab2e06e440e462b6d8a65e77d579277613fe3cfb31b4bded7cd34e7177d1`. It remains in a private cache and is not committed. Archive inspection found XeLaTeX template sources, examples, prior format documents, a Windows build/cleanup script and bundled font files requiring separate license/runtime review. No upstream script, TeX or binary was executed.

`fengrubei info` is offline. `fengrubei fetch` is cache-only by default, verifies exact cache size/hash, creates a new `0600` output without overwrite and leaves the ZIP packed. Explicit `--online` performs the allowlisted governed retrieval and atomically installs the verified original. Synthetic loopback proof exercises four unchanged five-second gaps, robots, one validated redirect, streaming integrity, cache reuse, no cookies, no overwrite and corrupt-cache rejection.

`cargo fmt --all --check`, strict all-target clippy and the final offline suite passed with **54 tests** and one ignored subprocess worker. Actual CLI proof reported pinned provenance, copied the governed observed artifact from verified private cache to an owner-controlled directory with matching size/hash, denied `/tmp` (exit 5), rejected a relative `--online` path before cache/network work (exit 2), rejected an existing destination (exit 9), and made no network request during the smoke. The feature does not promise current competition-format compliance, install fonts, compile a document or convert LPPL content into project MIT source.

Independent review found five defects. Runtime input validation occurred after cache/network access and the JSON schema did not enforce absolute/non-NUL paths; both are now aligned and validated before opening the cache. Output under an attacker-writable parent could be swapped after `create_new`; output creation now pins and validates an owner-controlled, non-writable-by-others, symlink-free parent, uses descriptor-relative creation/cleanup, enforces mode `0600`, and checks the final device/inode. Cache temporary allocation after acquiring the final asset lease could strand the governor; it is now reserved before that lease, with a regression proving only the first three governed requests occur and governor state remains known on failure. A restrictive umask could cause early validation failure and leave an empty output; all post-create operations are now cleanup-guarded and `fchmod(0600)` runs before validation. Focused contract and safety re-reviews reported no remaining concrete finding.
## Offline-tested gateway client
Issue #11 defines the safe gateway contract and issue #13 adds the two-phase logout follow-up. The implementation uses only TLS-validated `https://gw.buaa.edu.cn` challenge, portal and usage paths. Usage is cache-only by default and redacts username/real-name/MAC response fields. Login requires exact typed stdin intent plus a prior typed `resume-auth`; the challenge and final credential submission are separate governor leases with the final `Authentication` request consuming the only armed attempt. No request retries automatically.

Logout plans now generate fresh random operation IDs and bind username/IP/AC ID plus that operation into `plan_hash`. A same-account process-shared operation lock serializes receipt recheck through mutation and persistence without replacing the shared governor. After the final request lease is acquired and before send, an account-level unknown barrier is persisted; malformed/incomplete outcomes or receipt/journal failures keep it. The typed `logout-recovery-plan` / `logout-recovery-commit --offline` flow records only operator review, reports `remote_state=unknown`, sends no request, and tombstones the original operation.

Original Rust implements the XXTEA-style info field, custom base64, HMAC-MD5 password and SHA-1 checksum. An independent synthetic protocol vector pins expected output. Loopback coverage includes usage-cache reuse, governed challenge/login/logout, same-plan receipt reuse, a fresh plan committing separately, real subprocess contention with a delayed stale-miss boundary, failed pre-send journal preflight with no request, malformed 2xx recovery, failed receipt persistence, account-wide barriers and offline resolution.

The original implementation used an XEncode grouping that differed from the two pinned public references; its old synthetic vector encoded that same formula and was not an independent known-answer. Issue #30 corrects the grouping and replaces the vector.

Independent safety review found GW-AUTH-001: malformed/oversized successful 2xx credential responses could return unavailable while clearing the authentication latch. The transport now treats every absent/error application result on an `Authentication` request as indeterminate and compounds it with HTTP Retry-After/network facts, keeping the one-shot consumed and latch set. A malformed 200 JSONP regression directly verifies the durable fail-closed state; focused safety re-review reported no remaining finding.

Independent contract review corrected stale availability claims, aligned input character/control bounds and usage schemas, and qualified credential zeroization. The original login stdin buffer now zeroizes on command return and the parsed password zeroizes on every drop path.

The full offline suite passes with strict all-target clippy and formatting checks. The actual CLI rejects online recovery with `permission`/exit 5 and rejects malformed offline recovery input with `invalid_input`/exit 2 before any cache or network work. No external independent PR approval or maintainer merge approval is claimed; both remain required before merge or issue closure. No real campus usage, authentication, logout, recovery query or mutation was authorized or performed. The aggregate gateway acceptance remains partial/live-unverified.

**Operator-authorized live read (2026-09-25):** the account owner explicitly authorized read-only campus observations; the shared governor was raised to a 60-second request interval for the session. One governed `buaa gateway usage --online` attempt at ~2026-09-25T18:12:54Z and a second at ~2026-09-25T20:35:15Z (≈2 h 22 min apart) were both made through the governor, and earlier diagnostic TLS probes of the same hosts were made at a slower pace. Each governed attempt terminated at the network edge: TCP connect succeeded, certificate verification succeeded, and the TLS handshake was then severed (`SSL_ERROR_SYSCALL` / `unexpected EOF`) with zero response bytes; the CLI returned sanitized `unavailable` (exit 7). No campus request was completed, no credential was transmitted, and no endpoint behavior, account postcondition, `ip`/`ac_id` value may be claimed. The same severing was independently reproduced on `spoc.buaa.edu.cn` and `ihome.buaa.edu.cn` (TCP OK, certificate verify OK, handshake severed), and the operator confirmed that the account cannot log in from this devcontainer: the egress block is domain-wide, not credential-specific. No usable route to `*.buaa.edu.cn` exists here; a later live read requires reachable egress, the same shared governor, and the same read-only authorization.

## 2026-09-24: gateway XEncode formula repair

Issue [#30](https://github.com/cyjin-yl/buaa-cli/issues/30) identified that the previous Rust grouping `(A + B) ^ (C + D)` disagreed with both pinned research sources. The implementation now computes `A + (B ^ C) + D` using wrapping `u32` additions. Exact source commits, blob IDs and license boundaries are documented in [REFERENCES.md](REFERENCES.md#gateway-xencode-formula-review); the GPL source was read for formula corroboration only, not copied.

- The manual smoke used the actual `crypto::derive()` path with ASCII/normal-token and UTF-8/short-key synthetic inputs; all `info`, HMAC-MD5 and SHA-1 values matched the separate pinned-formula oracle. After removing the temporary runner, `cargo build --locked --offline` succeeded. The permanent vectors and automated tests remain unexecuted.
- No campus request, authentication attempt, user credential use or mutation occurred. Current campus gateway compatibility remains unverified; these public community references do not establish the live service's required formula.

Independent exact-head protocol review and maintainer approval are required before merge; the linked PR will carry the final review result.

## Official news-center listing

`buaa announcements list` reads the live university-wide news center on `news.buaa.edu.cn`, defaulting to `tzgg` (通知公告). Optional JSON filters are `category`, `page`, inclusive `since`/`until` and title-substring `match`. Page 1 is the latest listing; later ordinals must appear in its advertised pagination links (observed page 2 -> `tzgg/252.htm`, not `tzgg/2.htm`). No URL inference or automatic traversal. Other configured category layouts remain live-unverified. `announcements article` returns the selected page's `div.v_news_content` paragraphs, publish date and raw attachment-link hints, never attachment downloads. Historical replay stays offline and operator-asserted, not verified archive attribution.

Offline contract: empty/oversized HTML, missing row titles and empty listings fail closed; missing links and unparseable dates remain explicit instead of being invented. Date filters exclude entries without a parseable date. `ArchiveClient` returns `offline_miss` before governor/HTTP construction; the CLI maps this to `unavailable` (exit 7). `offline_lookup_with_empty_cache_reports_unavailable` proves listing/article misses in a private fixture without opening even its isolated governor. The adaptive CLI test checks cache-hit success or exit 7 without consulting HOME or unrelated cache files and passes with a misleading HOME. Operator cache contents are never removed or rewritten by these offline tests.

**Source drift (2026-09-29):** status diagnostics found HTTP 404 at `https://www.buaa.edu.cn/xwzx.htm`; successful governed adapter reads now use `news.buaa.edu.cn` (evidence below). Preserve earlier archive evidence separately: the 2026-09-23 CDX observations for the retired URL and university homepage returned three captures each; the homepage observation included 1997. Later old-adapter and Web Archive attempts returned sanitized `unavailable` (exit 7). Archive unavailability is not evidence of an original-host 404. Diagnostic status observations are not adapter functional proof.
`docs/index.html` is an original static, docs-first page informed by the [requested design reference](https://killaislop.com): neutral surfaces, restrained links, readable commands and explicit capability limits, without gradients or badge walls. Chromium rendered it at desktop and mobile sizes; anchor navigation worked and the mobile document had no horizontal overflow. The page loaded no external resources. Missing browser libraries were extracted privately inside this devcontainer for that proof; no private operational image recipe or host build was used.
The initial Pages release used main `26babf37a3e4f898af8988ad945e2af6aadfa9c4`; the current deployed build and browser verification are recorded above. This is not a claim of live campus/archive verification or a privileged CI bridge.
## Verified local recording catalog iteration
[Issue #3](https://github.com/cyjin-yl/buaa-cli/issues/3) binds this local-only slice to the broader recordings/Life acceptance items. Work lives in the project-owned `recording-catalog` worktree and branch, initially stacked on the publication-receipt change. Only non-sensitive table/field/key/relation/FTS facts were reviewed through authorized APIs; the Rust reader, resolver and synthetic SQL fixture are original. No private catalog records, media, credentials, defaults or private implementation were copied.
- Added `recordings search`: explicit operator attestation before file access, read-only bounded SQLite FTS5 queries, opaque catalog/query-bound keyset cursors, preserved nullable timing, and separate declared original/derived asset hashes and object locators. Operator attestation does not verify rights or grant campus permissions.
- Before the signed-rowid follow-up, the offline suite had **71 passes**, one intentionally ignored subprocess worker, strict all-target clippy, and formatter checks. This earlier suite did not cover non-positive IDs.
- Actual CLI smoke traversed two synthetic result pages, checked distinct source/derived hashes and null timing, rejected cursor/query mismatch (exit 2), denied missing authorization (exit 5), and confirmed catalog file bytes unchanged. No network or object fetch was used.
- Independent review found RC-1: depth-insensitive ancestry memoization could omit an original reachable by a shorter path. The targeted deep-first/shared-shortcut fixture failed before the fix and passed afterward. Resolution now tracks best depth, revisits retained edges with improved budget and clears recovered depth-limit issues. Contract re-review confirmed the correction; the catalog safety review found no concrete issue.
- Results remain catalog declarations, not verified blob contents or complete history. SQLite WAL coordination sidecars may change even though catalog/schema data does not. Different requests do not share a frozen snapshot. Remote object-store retrieval, media intake/transcription/repair and complete parent capabilities remain pending.

## 2026-09-24: signed SQLite recording pagination

Issue [#39](https://github.com/cyjin-yl/buaa-cli/issues/39) identified the mismatch between an accepted SQLite `INTEGER PRIMARY KEY` rowid column and the first-page `id > 0` sentinel. The reader now uses no lower bound on the first page, a signed `i64` cursor on later pages, and separate validation for signed segment IDs versus non-negative segment indexes/times. The output schema declares the full signed 64-bit ID range.

- `cargo build --locked --offline` succeeded in `work/recordings-signed-id`. An independent review found missing timing fields in the first schema revision; the fields and regression assertions were restored and manually checked. Automated tests were not run; the in-source signed-rowid regression remains unexecuted.
- Manual CLI smoke on a private temporary synthetic catalog with synchronized FTS entries `id=-1,0,1` and `limit=1` returned those three IDs in order over three pages, with `more_results` true/true/false and a null final cursor. Every result declared `network_access=false` and `source_objects_fetched=false`.
- After the schema correction, `buaa schema` showed signed i64 bounds for `segment.id` and nullable non-negative integer `start_ms`/`end_ms`; a fresh manual CLI page returned `id=-1` with both timing fields null.
- No private Life catalog, media, object store, campus endpoint or credentials were used. The static rowid review and official SQLite references do not imply that real Life producers emit non-positive IDs; aggregate recordings/Life acceptance remains partial.

## 2026-09-30: Life storage read-interface source evidence

Live GitHub API permission checks confirmed authorized read access to the private Life repository. Source inspection was pinned to `af59427c7f6bac3382b5989b811b69872f4de928`; three relevant media-tool source files were loaded privately and inspected with a structural Python AST script. Only non-sensitive interface facts were emitted: S3-compatible HeadObject/GetObject bucket/key operations; a body digest loop reading 262,144-byte chunks; SHA-256 computation; and stream closure in finally. The inspector delegates to existence and digest helpers. A separate PutObject workflow exists and is not adopted. No private code was executed or copied; no endpoint, credential configuration, catalog record, media bytes or object-store response was printed or committed.

The draft in `docs/RECORDINGS.md` binds these facts to the existing original/derived catalog descriptors and names the next prerequisites: owner-approved HTTPS egress/authentication/immutability and byte-budget contract, rights-cleared exact object inventory, private credential delivery and synthetic streaming/error fixtures. It is not a remote adapter, approved service contract, verified blob or proof of course recording rights. `recordings` and `life` stay partial; issue #47 stays open. The public CLI's hash_verification remains catalog_declared_not_blob_verified and source_objects_fetched remains false.

`cargo build --locked --offline` succeeded with the updated acceptance manifest. The real `buaa capabilities` command exited 0 and reported Life as partial, the pinned source head and pending owner approval. This investigation changes only evidence/documentation, not the recording-search runtime contract; no new tests or object request were added. [Issue #74](https://github.com/cyjin-yl/buaa-cli/issues/74) requests owner review and private operational prerequisites. Independent exact-head approval remains required before merge.

## Authoritative organization directory observation
The owner authorized up to three official public reads. The production shared governor held each request through bounded response processing/private evidence persistence, with one in flight and at least five seconds after completion. TLS validation remained enabled; redirects, proxies, cookies, decompression and automatic retries were disabled. No login or mutation occurred.
1. `https://www.buaa.edu.cn/robots.txt`: HTTP 404, SHA-256 `a71f7d336711705a8ac403fc504633df3f32cf29973fd72a6d6099a032818aed`.
2. Official homepage: HTTP 200, SHA-256 `b936471fe3aaad7ae6e4753b0183f347fd637aaa18c59ecf893c6703c3911ebd`; linked `jgsz/jxkyjg02.htm` as 教学科研机构.
3. Linked directory: HTTP 200, SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`.
The Rust production parser processed the privately retained response offline as six categories and 50 entries, including six hidden source entries, five missing hrefs and one non-HTTP href. Raw HTML is not committed. `docs/data/organizations-2026-09-20.json` preserves normalized public facts, exact listed hrefs, source order, hashes and scope limitations. It does not claim the source document covers every university unit or that linked sites are reachable/current.
`organizations list` is cache-only by default. Its explicit online modes permit only the official robots/directory routes, conditionally revalidate cached data and use the same shared governor. Synthetic loopback proof exercises robots 404 handling, unchanged five-second spacing, cache hits, no cookies and denied off-route egress. Announcement list/full-text/attachment retrieval is still pending.
Verification after integration: `cargo fmt --all`, strict all-target clippy and `cargo test --locked --offline` passed with **54 tests** and one intentionally ignored subprocess worker. The actual CLI exposed help/schema, returned an offline cache miss without network opt-in (exit 7), and rejected conflicting network modes (exit 2). The Rust production parser processed the authorized recorded response as the same six/50/6/5/1 counts in the normalized snapshot. Independent safety review found no concrete defect in the fixed egress/cache/governor refactor; production DNS/TLS behavior remains bounded by the three recorded observations rather than an unlimited crawl.
Independent contract review found three parser defects: a changed group could contribute no entries while the document still succeeded, literal href whitespace was lost before provenance output, and category control characters were accepted. Focused regressions reproduced the exact cases. The parser now requires at least one entry per recognized group, preserves the raw href while trimming only for URL resolution, and rejects category controls. Post-fix parsing of the private official response retained the six/50/6/5/1 evidence counts; focused re-review reported no remaining concrete finding.

## 2026-09-24: Retry-After year arithmetic

Issue [#41](https://github.com/cyjin-yl/buaa-cli/issues/41) found that oversized IMF-fixdate/asctime year tokens could reach unchecked timestamp arithmetic. Those formats now require exactly four year digits before conversion; calendar-to-Unix-millisecond conversion uses checked operations and rejects overflow. Existing Retry-After status-specific fallback behavior is unchanged. The separate RFC 850 rolling two-digit-year rule tracked by [#33](https://github.com/cyjin-yl/buaa-cli/issues/33) was not changed.

- `cargo test --locked --offline`: **113 passed** across five suites, one ignored. Strict all-target clippy and `cargo fmt --all -- --check` passed. Focused parser/format regressions passed in both debug and release profiles.
- A temporary local Rust smoke exercised `RequestLease::finish`: oversized IMF/asctime dates on 503 yielded no cooldown/latch; an oversized IMF date on 429 retained the existing 30-minute fallback; valid four-digit 2100 IMF/asctime dates produced future cooldowns. The temporary runner was removed. No network, campus endpoint, authentication or mutation was used.

## 2026-09-24: Memento archived-status boundary

Issue [#44](https://github.com/cyjin-yl/buaa-cli/issues/44) identified that transport/governor status handling ran before Memento attribution. Exact capture responses now validate `Memento-Datetime` against the requested timestamp and the `rel=original` Link against the requested original before classifying 4xx/5xx as archived-resource status. The raw HTTP status and replay bytes remain in `archive_reported_http`/`immutable_original`; historical 401/403/429 and their `Retry-After` no longer latch or cool down the current shared source governor. A real `CF-Mitigated: challenge` remains authoritative, and body failures still retain their independent backoff.

- `cacheable` and `valid_cached` now cover the same attributed 4xx/5xx replay domain. Offline cache hits run the same exact provenance normalization. Unattributed or mismatched 401/403/429/500/503 retain current-source latch/cooldown/rejection handling; unattributed 404/410 remain query-scoped gaps.
- `cargo test --locked --offline`: **108 library tests + 8 CLI tests passed**, one ignored subprocess worker. Strict all-target clippy and `cargo fmt --all -- --check` passed. Loopback regressions cover valid 403/429/500/503, invalid attribution, true challenge precedence, 404/410 gap/capture cases, and offline cache round-trips.
- This was entirely local synthetic loopback testing. No live Internet Archive replay, campus endpoint, authentication, or mutation was attempted; deployed Wayback status behavior remains unverified.

- Independent fresh-context review of PR #52 head `faffe2e1fd9892429cc26bd2b723a9047c2d36a7` reported no concrete source findings. The review did not rerun tests; verification remains the recorded offline suite/clippy/format checks.

## 2026-09-24: RFC 850 Retry-After year window

Issue [#33](https://github.com/cyjin-yl/buaa-cli/issues/33) identified the fixed 1950/2050 pivot and a late-2076 timestamp that exceeded the RFC cutoff. RFC 850 dates now compare the full candidate timestamp with the captured UTC reference plus 50 calendar years; older out-of-window candidates roll forward to preserve the current 100-year window. The same wall-clock sample drives this comparison and conversion to the monotonic governor deadline. At reference `2026-09-24T05:40:00Z`, `75`/`76`/`77` map to 2075/2076/1977, while `31-Dec-76T23:59:59Z` rolls back to 1976.

- Deterministic parser regressions compare 75/76/77 and the late-2076 cutoff case with equivalent four-digit IMF dates; a 2099 reference verifies `00→2100`. A real governor 503 regression constructs a valid RFC 850 date 49 years ahead and verifies its durable cooldown remains more than 40 years beyond the ordinary request gap.
- The full-timestamp boundary and 503 regressions pass in debug and release profiles. Full `cargo test --locked --offline` passes **110 library + 8 CLI tests**, one ignored subprocess worker; strict all-target clippy and formatter checks passed.
- All verification is offline with an isolated governor state. No live HTTP request, campus endpoint, authentication, or mutation occurred.

## 2026-09-26: archive resume cursor query-scope binding

Issue [#49](https://github.com/cyjin-yl/buaa-cli/issues/49) showed that reusing a CDX resume cursor under a different query scope (url/from/to/limit) makes the upstream iterator start mid-range and silently skip captures. The adapter is the sole cursor producer, so each issued `next_cursor` is now bound to the exact query identity that minted it in a bounded private registry (`cursor-scope.json`, 0600, atomic writes, capped entries) inside the shared archive cache directory. Presenting a cursor under any other scope, or one the adapter never issued, fails closed with `cursor_scope_mismatch` before any request; same-scope continuation is unchanged and the server token passes through untouched.

- Loopback regression `net::tests::lookup_cursor_is_bound_to_the_query_that_minted_it` verifies same-scope page continuation, cross-scope rejection with zero additional HTTP requests, unknown-cursor rejection, and binding persistence across client instances sharing the cache directory.
- `net::tests::cursor_scope_registry_evicts_at_the_entry_cap` seeds the registry at the 256-entry cap and verifies the next recording evicts the stale bindings deterministically, so a full registry keeps recording new bindings instead of ratcheting into the corrupt-cache state.
- Full `cargo test --locked --offline` passes **112 library + 8 CLI tests**, one ignored subprocess worker; strict all-target clippy and formatter checks passed. All verification is offline; no live HTTP request occurred.
## 2026-09-30: School Six 2020 reference credit checks

`credits school6` is an original offline calculator using numerical requirement facts from the pinned community reference `TrickEye/can_I_Graduate` at `5e0f0355455d7eb7e69f953a23ca405e5af7ebed`. The repository default branch is master and no license is declared; no upstream implementation was copied or executed. This is not an approved university contract or validated full course catalog. The reference describes 150 total credits, per-category minima and single-course English/cross-major/humanities qualifications.

Course identity, earned status, category and qualifying attributes are explicitly supplied by the operator. Repeated stable IDs count once if any listed attempt passes, conflicting identity metadata fails closed, and qualification witnesses do not add credit again. Exact hundredth-credit arithmetic avoids floating threshold drift. A category deficit remains visible even if total credit is 150. Output always marks graduation eligibility not verified; official retake/waiver/substitution/overlap rules remain unresolved and credits acceptance stays partial-offline.

Actual CLI smoke used a separately calculated Python Decimal fixture: all category thresholds and qualifying witnesses yielded exactly 150 credits; removing engineering and moving its 9 credits into math retained total 150 but reported an engineering deficit of 9; failed/repeated attempts counted once with two collapsed duplicates; invalid input exited 2 without echo; the existing School-8 sample still counted 2 credits. Five focused edge regressions passed. The old School-8 source-constant/schema-plumbing tests were removed, not repinned. [Issue #76](https://github.com/cyjin-yl/buaa-cli/issues/76) binds this bounded slice to the broader acceptance item. Independent exact-head and maintainer policy review are required before merge.

Local contract review found that the source explicitly permits a non-practical English exchange course regardless of the primary credit category. A new regression failed before the fix; `english_exchange` is now a separate operator attestation from the local elective `english` route. The real CLI accepted an attested two-credit math-modeling exchange witness with the same 150-credit total. Six edge regressions and 17 focused credits tests pass; this remains an asserted reference check, not verification of the exchange or course rights.

Final exchange-aware offline gate passed: `cargo build --locked --offline`; `cargo test --locked --offline` (184 passes across the suites, 2 ignored); strict `cargo clippy --locked --offline --all-targets -- -D warnings`; and `cargo fmt --all -- --check`. The actual help command lists `credits calculate|school6`, schema exposes the bounded operator-input contract, and capabilities reports credits as partial-offline with community-reference provenance. The temporary inspected upstream source was removed; only its linked numerical facts inform the original Rust implementation.

## 2026-09-26: announcements history provenance assertion

Issue [#34](https://github.com/cyjin-yl/buaa-cli/issues/34) showed that `announcements history` labelled any same-shape HTML bytes as the official BUAA historical snapshot, because raw bytes carry no Memento headers and the old contract required nothing from the operator. The stdin contract is now a JSON document: `html` (base64 UTF-8, ≤ 2 MiB decoded) plus an explicit `provenance` assertion whose `source_url` must exactly equal the official listing URL, with an optional 14-digit `capture_timestamp`. The output echoes the assertion under `provenance.status = operator_asserted` with an explicit note that archive response headers were not supplied, and binds the supplied bytes by SHA-256 in `retrieval`.

- Regression `announcements::tests::history_requires_operator_asserted_provenance` verifies the parse reuse, asserted-provenance echo, SHA-256 byte binding, null-when-omitted timestamp, and fail-closed rejection of a foreign `source_url`, missing provenance, malformed base64, and an invalid calendar timestamp.
- Full `cargo test --locked --offline` passes **114 library + 8 CLI tests**, one ignored subprocess worker; strict all-target clippy and formatter checks passed. All verification is offline; no live HTTP request occurred.

## 2026-09-28: SPOC public surface probe and governed observation

On 2026-09-28 egress to `spoc.buaa.edu.cn` recovered (INCO middleware, HTTP 200, `newSpoc` session cookie); the 2026-09-25 domain-wide block no longer covers SPOC. A read-only, contract-evidence command `buaa spoc surface` was added. It is not an authenticated adapter: it fetches the two fixed public paths through the shared process governor (robots policy checked first) and reports only sanitized structural facts — status, content type, byte length, SHA-256, document title and form shape. Response bodies, field names and values never enter output, logs or the repository; no authentication is attempted and no mutation is possible.

- Egress whitelist: host `spoc.buaa.edu.cn`, no query, paths `/`, `/spocnew/`, `/robots.txt` only. Cache directory `.buaa-cli-spoc-cache`. Redirects are not followed (the client's no-redirect policy), which is how the canonical `/spocnew/` trailing-slash path was discovered.
- Governed observation (one in flight, shared 60-second raised interval, TLS validation on, no cookies/redirects/proxy/retry): `robots.txt` HTTP 200 (998 B); root `https://spoc.buaa.edu.cn/` HTTP 200, SHA-256 `373cd4cd521ae2c33d27ce647d416b6a4d44523e100fa8503fd7f984af355243` (377 B, a JavaScript redirect stub to `/spocnew`, no `<title>`, no server-rendered `<form>`); entry `https://spoc.buaa.edu.cn/spocnew/` HTTP 200, SHA-256 `5b6709aa5aafd07227e9348c619a5b0e07bff36059fc0ea33e8c1e6c897cdf9f` (2173 B, `<title>智学北航</title>`, no server-rendered `<form>`).
- Contract-relevant finding: the SPOC login surface is client-side (no server-rendered form on either public page), so any authenticated contract must discover endpoints from the client bundle, not by scraping a form. This is recorded in the draft contract `docs/SPOC.md`.

Verification: `cargo test --locked --offline` passes **117 library + 8 CLI tests**, one ignored; strict all-target clippy reports 0 warnings; `cargo fmt --all -- --check` is clean. `spoc surface` is cache-only by default; `--online`/`--refresh` are explicit. The SPOC acceptance item remains **blocked**: the surface probe is contract evidence, not a service contract, and the owner-reviewed contract plus rights-cleared course inventory are still required before any authenticated read.


## 2026-09-29: announcements news-center migration

The announcements acceptance item remains **partial-live-verified**. University-wide news-center reads do not complete the all-college matrix: per-college CMS adapters, genuine faculty/college filters, attachment bytes and complete historical coverage remain missing. The operator confirmed college boards have different layouts; no linked college site was crawled for this slice.

Governed, read-only proof (TLS verification enabled; one process-shared governor; no authentication or campus mutation):

- `announcements list --online` read `https://news.buaa.edu.cn/tzgg.htm`: HTTP 200, 5 entries, 20,653 bytes, SHA-256 `9021f2b387ae3fd2273692e7f7b05936775cea78eec86a5c32d0fd680c3937a1`, fetched at `1790713000641` Unix ms. An offline follow-up returned `cache_status=hit` with the same bytes.
- `announcements article --online` read `https://news.buaa.edu.cn/info/1010/69802.htm`: HTTP 200, 19,749 bytes, SHA-256 `80f4c3243e6cf2629ee4d908a6fd5d51d246659c44c8e5aaebf27d5480b2c87f`, fetched at `1790713252798` Unix ms; 26 paragraphs, publication date `2026-09-15`, no attachment hints in this sample. Synthetic fixture proof covers attachment hints; no live attachment was fetched.
- `announcements list --refresh` completed conditional revalidation with HTTP **304**, `cache_status=revalidated`, `revalidation_status=304`, at `1790724706337` Unix ms. The original fetch timestamp and SHA-256 were preserved. Original response HTTP facts remain separate from revalidation metadata.
- The first cold-robots attempt cached `news.buaa.edu.cn/robots.txt` HTTP 404. That request consumed the shared lease; the subsequent content acquisition exited 8 (`rate_limited`) because the raised 60-second interval exceeded the 30-second bounded wait. It did not issue the listing request. The later deliberate request succeeded after spacing was checked. No auto-retry, parallel governor or policy relaxation was added. Uncached pagination discovery can require a second governed content request and has the same bounded-wait constraint.

Source review corrected two regressions before publication: paged historical sources such as `/tzgg/252.htm` were incorrectly rejected, and page ordinals had been mistaken for numbered filenames. The paged-history regression failed before the fix and passed afterward; pagination now follows only an explicitly advertised, same-category link. URL credentials, custom ports, queries, fragments and foreign hosts remain rejected. `history` accepts optional `asserted_by`, emits `type=announcements_history`, and binds supplied HTML with `retrieval.sha256`; it never performs an archive request or verifies the assertion as a Memento fact. The retired source's older HTML layout is not supported by the new parser; retained CDX metadata is not reconstructed content.

Actual offline CLI smoke exercised a date/title-filtered cached listing (one match), `null` default input (five entries), cached article text (26 paragraphs), and a synthetic paged history replay with correct relative-link resolution; all exited 0. The corrected gate passed `cargo build --locked --offline`, `cargo test --locked --offline` (**172 library + 18 CLI passed, 2 ignored**), strict `cargo clippy --locked --offline --all-targets -- -D warnings`, and `cargo fmt --all -- --check`. Independent exact-head review and explicit maintainer approval for the changed source contract remain pending; no approval or merge is inferred from local review. The live repository reports ADMIN permission and no branch protection, which does not waive these contributor-policy gates.

The real CLI also returned the cached default listing from a TTY without any stdin data, completing within a five-second smoke deadline. The updated local Pages document was rendered in Chromium at 1280×900 and 390×844; the changed announcement row was visually checked and the document had no horizontal overflow. This is local surface proof, not a claim that the unmerged update has been deployed to GitHub Pages.

Follow-up test-safety review pinned the test-only offline client's fallback transport to loopback port zero as well as an isolated governor. The tested offline path still opens neither governor nor HTTP transport; if a later regression reaches transport, this fixture no longer targets the real news host with a test governor. Production clients, governor policy and cache identity are unchanged.


## Maintainer-authorized independent review fixes

Fresh exact-head reviewer ReviewNewsBase found three P2 defects at 50d8d059a9686bded9404b63e696fa873145f0eb: repeated latest-page revalidation before selected-page refresh, signed ISO-year acceptance, and oversized hrefs being mislabeled missing. Discovery now uses a retained cache-first reference before switching the same client/cache identity to the selected request policy; date components require ASCII digits; present over-budget hrefs fail closed before copying. Focused regressions and cached/invalid CLI smoke are re-run before new-head approval. No governor timing or account safety policy is relaxed.

## 2026-09-30: independently observed computer-college notices

The cached official directory binds 计算机学院 to the preserved HTTP href `http://scse.buaa.edu.cn/`; this slice explicitly observes HTTPS separately through the same process-shared governor. Homepage and robots, the source-advertised `/xwgg/gggs.htm` board, its advertised ordinal-2 `/xwgg/gggs/1.htm`, and notice article categories 1099/1299 have narrowly scoped egress. Other college boards are not covered.

Governed read-only proof: robots HTTP 404 was cached; the first content acquisition exited 8 under the raised 60-second interval/30-second bounded wait, without issuing the content request. After diagnosis and fresh governor spacing checks, the root returned HTTP 200 (40,702 bytes), the notices index HTTP 200 (27,594 bytes), and a public policy article HTTP 200 (27,947 bytes). Exact hashes are in acceptance.json. No authentication, campus mutation, credential use, parallel limiter, auto-retry or TLS bypass occurred.

Actual college-specific listing behavior: 10 current-page entries, 5 entries on advertised page 2, and 3 entries since 2026-09-01. Split year/month-day dates and `p.bt` titles are parsed independently of the news-center layout. History remains offline, byte-bound and operator-asserted; original historical HTTP URLs are not silently upgraded.

The selected policy article uses an English timestamp and contains image/PDF preview scripts, not plaintext policy paragraphs. The real cached CLI reports `embedded_document`, publication date 2026-09-07, zero prose paragraphs, 11 attachment hints and 12 source-declared derived preview paths. No document/image/attachment bytes were fetched, no OCR occurred and no missing text was reconstructed. A regression exposed JavaScript being reported as article text; it failed before the shared text-filter correction and passed afterward. Executable, style, template and noscript payloads are excluded.

Focused offline proof covers source-scoped paging, HTTP history/link preservation, unknown-date filtering, image-only documents, opaque JSP attachment hints and rejected credential/query/category routes. Overall announcements acceptance remains partial; public college responses supplied no conditional validators and live Memento replay remains unverified. Independent exact-head review and source-contract maintainer approval are required before merge.

Final college gate: offline build, full tests (**177 library + 18 CLI passed, 2 ignored**), strict all-target clippy and formatter check passed. Real offline history smoke preserved the HTTP original, resolved its relative article link and matched the supplied-byte SHA-256; the university default still returned five cached entries. [Issue #78](https://github.com/cyjin-yl/buaa-cli/issues/78) binds the bounded source slice. Exact-head independent review and maintainer approval remain pending; no complete-all-colleges or original-document-text claim is made.


## Maintainer-authorized college history review fix

Fresh reviewer ReviewCollege found SCSE historical notices mislabeled as university news-center snapshots. The historical board label now follows the selected source, retaining 公告公示 for the college and the original news-center label only for news-center sources. A source-identity regression failed before the fix and passed afterward. HTTP provenance remains unchanged. Updated exact-head review is required.

College integration onto reviewed main preserves the source-scoped paging predicate and parent cache-first refresh fix. The same reviewed absent-versus-rejected link budget is applied to college rows before allocation; no source profile, governor identity or throughput limit is relaxed. Updated-head focused announcements tests/build/strict clippy pass.

## 2026-09-30: source-bound original policy PDF

`announcements document` resolves a PDF only from the observed college article viewer's first literal argument, with no script execution, arbitrary URL input or inference from derived preview names. The retained source article SHA-256 is `6b9a717ae00c83eed33e6a0378548c7cb25fef3875ba40671302204f0f33e8c7`. The source namespace has opaque filename token widths 27/8 plus a bounded hexadecimal suffix; an initial mistaken 32-character assumption was rejected before document transport and corrected from the cached source, not by probing more URLs.

The real shared-governor GET returned HTTP 200/application-pdf, **406,588 bytes**, SHA-256 `cc829e9a40ef539b36ce674699367a1872c47b485aa1a47750481a45301fe2c2`, fetched at `1790751665278` Unix ms. Independent base64 decode/length/hash checks and cache-only CLI replay passed. Conditional PDF revalidation returned HTTP **304** at `1790753276444` Unix ms, preserved the original fetch timestamp/SHA, and read its source article from cache. Document refresh changes only cache policy on the same source directory/governor identity; refresh the article separately to update the declaration. No automatic retry, other asset fetch, TLS bypass, credential use or campus mutation occurred.

The original PDF's policy text was readable through the operator document reader. That inspection is a derivative of the exact retrieved original; the CLI returns original bytes and does not perform text extraction/OCR. The webpage's scripts/previews remain non-prose and are not substituted for the original. The 12 derived preview images and 11 other attachment hints were not fetched. Private inspection copies stay outside source and are removed after proof; private cache retains byte-bound originals.

PDF checks cover MIME/header/EOF framing only, not active-content safety, a publisher signature or an external published checksum. Document URLs are immutable in the byte cache; the existing transport rejects changed retained bytes. Source declaration/query/foreign-route/concatenation and truncated/HTML-body regressions pass. Full locked offline gate: **180 library + 18 CLI passed, 2 ignored**; build, strict all-target clippy and formatter checks clean. Invalid foreign/HTTP/query source inputs exit 2 without output. [Issue #80](https://github.com/cyjin-yl/buaa-cli/issues/80) binds this bounded slice; independent exact-head and maintainer source-contract approval remain pending. Announcements acceptance stays partial.


## Maintainer-authorized independent document review fixes

Fresh security reviewer ReviewDocuments identified DOC-001 (inactive comments/strings could establish original-PDF provenance) and DOC-002 (recognized PDFs without previews were rejected or mislabeled full text). Both regressions failed before the fixes and pass afterward. A bounded, non-executing recognizer now accepts complete supported top-level viewer calls outside comments/quoted text, with exact identifier/call context and complete literal argument grammar; unsupported active forms fail closed. Recognized original PDFs and derived previews independently indicate unextracted document content. Original-only pages return embedded_document and prose-plus-PDF pages partial_text. A real retained college article still resolves its declared original with zero policy paragraphs. No script execution, new source requests, or PDF safety/publisher-authentication claim is introduced. Updated exact-head review is required.

Document eligibility re-review additionally covered HTML legacy comments, CR/LF/Unicode line terminators, non-executable script MIME types, external-script fallback bodies and active template interpolation. The bounded recognizer now honors classic-script eligibility, ignores inactive data, handles line comments at supported terminators and fails closed on unsupported active module/interpolation forms. Updated-head focused announcements tests/build/strict clippy pass; complete integration still requires exact-head re-review.

## Maintainer-authorized independent exact-decimal review fix

Fresh reviewer ReviewCredits found that f64 deserialization could round 1.99999999999999999 into a valid two-credit witness. Credit JSON tokens are now retained with serde_json raw_value and converted to checked integer hundredths before floating-point conversion; no rounding is used for input classification or course identity. Actual CLI rejects that token (exit 2), accepts exact 0.29, 200e-2, 2.000000000000000000000000, 1e2 and 1e-2, and rejects 100.01. The source remains an operator-asserted community reference, not graduation certification. Updated exact-head review is required.

## 2026-10-24: universal classroom form final admission

Historical exact-source gate `5738e8c6831831845ae5059fb50651668354e9678c12dfe98a42e36eec255550` passed 466 library/19 CLI cases, strict clippy, fmt, build, manifest equality and source/governor stability, but its fresh review found CSS token and split-text gaps. The next exact-source gate `7cc8d3f0a5883dd12f83c10bae23214475ff28495c8d58f098edc79e67b920bd` passed 467 library/19 CLI cases, then failed independent review on template-owned credential fields, cross-form interaction controls and raw-source vetoes from inert payloads. Those findings are fixed: template/script/style/noscript descendants cannot establish credentials or enter selected-form payloads; active challenge controls and labels are checked across the page while payload remains selected-form-only; final/probe text vetoes use one active DOM text walk and exclude inert code/template payloads. Datalist descendants and ordinary inert-attribute values remain forwarded in accordance with the observed Chromium FormData contract. The `none%` alpha spelling is refused.

The current module SHA `d58ed3f6ecb3eb156ffb43ae487960352d0da977bc690bebe0909ddb8ebed722` passes 58 session-focused cases with formatter, stable source, unchanged production governor and zero campus requests. Its full native gate and fresh complete-source approval remain pending, followed by the prepared single governed online authentication. No password has been submitted under this source contract.

## 2026-10-24: bounded form/parser and Cookie contract

Independent review of SHA `12d326a29a678f717fff2d7aa3cb8f13d575647724b92d98df20797fe48cc6eb` found template-option, range step-base, date/URL/datetime normalization, CSS color syntax, request-body CRLF, Cookie quoting/prefix, DOM-work, raw-error-text and MIME interpretation gaps. The current source applies exact browser-observed form defaults and wire normalization, excludes template-derived successful values while preserving datalist/inert-attribute entries, enforces cookie prefix flags/provenance and quoted values, and bounds DOM/text subtrees before submission. Failure classification and challenge vetoes now derive only from active DOM text facts; final JSON is not interpreted as embedded HTML. This SHA `f3f559000fdb2b535a0a1f6c089760dec67116cd11b7cbd23ea423665432d3f4` passes 65 focused session tests with stable source, unchanged governor and zero campus requests. A full native gate and fresh complete-source review remain pending; authenticated online confirmation has not yet run.

Later, that exact SHA passed a full native gate (468 library, 19 CLI, three ignored workers; strict clippy/fmt/build, manifest equality and stable source/governor, zero campus requests). Its fresh review found that initial credential pages did not scan text-only active markers before POST. The current source applies the same review-only predicate to the initial page and exposes it in inspection without reporting an active challenge. SHA `12d326a29a678f717fff2d7aa3cb8f13d575647724b92d98df20797fe48cc6eb` passes all 59 session cases with stable source and unchanged governor. Its complete native gate, fresh complete-source approval and one deliberate governed authentication remain pending; no password has been submitted under the new contract.
