# Authorized local recording segment lookup

`buaa recordings search` reads an existing, operator-authorized Life-compatible SQLite catalog. It performs real FTS5 queries and resolves catalog ancestry; it does not download a recording, contact a service, authenticate, repair audio, transcribe media or modify catalog/schema data. Remote object-store integration remains a separate pending capability.

The interoperability profile uses reviewed non-sensitive field, key, relation and FTS semantics. The implementation and fixture SQL are original. No private implementation, record, media file, operational default or credential is included in this project.

## Input and output

```sh
printf '%s\n' '{
  "catalog":"/private/catalog.sqlite",
  "query":"linear algebra",
  "authorized":true,
  "limit":20
}' | buaa recordings search
```

The path is an example: supply an existing local SQLite catalog that you have permission to read. `authorized: true` is an operator attestation, **not verification of media rights or a grant of campus/remote permissions**. It is required before catalog access; there is no interactive prompt or automatic private-catalog discovery. Results may contain private transcript text and object locators; do not forward them to public logs, issues or fixtures.

Input is JSON on stdin, output is one JSON object on stdout, and errors are sanitized JSON on stderr. `buaa schema` exposes exact input/output schemas. Optional `asset_id` restricts matches to that exact segment-owning asset. Limits are 1–100 hits (default 20). The literal phrase uses the catalog's `unicode61` tokenizer and searches text, not speaker names. It is not an arbitrary substring search; quotation marks and query-language operators in input do not become executable FTS/SQL syntax. The catalog's FTS5 index is external-content and keeps no copy of the text, so each returned segment is re-verified against its current text with the same tokenizer before it is reported; a desynchronized index row whose text no longer matches the phrase is dropped from the reply.

Replies contain segment text, its UTF-8 SHA-256, timing, and provenance keyed by segment-owning asset ID. The segment-text hash verifies only retrieved text, not the original media or the entire transcript asset. The raw query and local catalog path are not echoed; query and catalog identity bindings are reported instead.

Pass `next_cursor` unchanged as `cursor` to obtain the next page. It binds the normalized phrase, exact asset filter and catalog identity. The identity hashes the canonical path plus the device/inode of a descriptor the CLI opens on the catalog, and keeps that descriptor open for the catalog's lifetime so the binding refers to the file actually opened, not to two pathname stats bracketing it; it is **not a content hash or authorization token**. Results are ordered by increasing signed SQLite `INTEGER PRIMARY KEY` value; the segment ID and cursor preserve the full signed 64-bit rowid range described in SQLite's [rowid documentation](https://www.sqlite.org/rowidtable.html). One read transaction makes a request internally consistent, but a changing catalog is not frozen across separate pages; that limitation is explicit in every reply.

## Original and derived provenance

The reviewed tables are `asset`, `asset_relation`, `transcript_segment` and the external-content FTS5 index `transcript_fts(text, speaker)`, backed by `transcript_segment.id`. Asset descriptors retain ID, kind, bucket/key, recorded SHA-256 and size, MIME type, capture/ingestion facts, source, language and privacy. Arbitrary `metadata_json`, tags, ingest-event details and credential configuration are not read.

Only outgoing `transcript_of` and `derived_from` relations are ancestry links. Terminal audio/video assets are catalog-reported original candidates; they stay separate from the segment-owning transcript/derived asset. Multiple originals are returned explicitly. Alternate/superseding/manifest relations are not silently reinterpreted as ancestry.

Resolution is bounded to 16 ancestry hops, 64 loaded asset IDs and 128 retained edges. Missing assets, cycles, non-original terminals and resource limits produce explicit issues and incomplete provenance. A shared ancestor in a diamond is not a cycle. Dangling targets do not acquire fabricated hashes. Missing capture and segment timing remain null; ingestion time never substitutes for capture time.

`hash_verification` is always `catalog_declared_not_blob_verified`. Bucket/key fields are catalog locators, not proof that an object was fetched or exists. This command does not verify or disclose object-store credentials and does not reconstruct missing originals or history.

## Native classroom subtitles — supplied import

`buaa recordings subtitles` imports one explicitly selected timed track from an already retained, operator-authorized classroom-native response. It performs no network request, authentication, media download, transcription, catalog write or attendance/completion action. The original response remains caller-owned and is never persisted or reconstructed by the command.

The strict input contains `authorized`, `format: "classroom-native-v1"`, the exact response as Base64, its lowercase SHA-256, and both native selection fields: `sub_id` and `resource_guid`. Exactly one track must match both values. An empty source `resource_guid` remains an explicit missing association; the importer does not borrow an identifier from another response or invent a media link. The envelope must be successful (`status: 200`, `data.code: 0`) and the selected `all_content` array must be valid in full.

All selected cues are validated before any successful output. Current support is non-negative integer `BeginSec`/`EndSec` values converted with checked multiplication to milliseconds; fractional or string times, inverted intervals, malformed late cues and oversized text fail closed rather than being rounded, truncated or partially emitted. Cue order, repeated/overlapping intervals, exact text/translation, whitespace and escaped controls are preserved without sorting, deduplication, speaker/language inference or fallback to unsegmented transcript text. The original-byte hash and exported-segment hash are separate; the latter is computed from the actual compact JSON `segments` value in output field order.

Bounds are 4 MiB decoded input, 256 tracks, 20,000 selected cues, 256-byte identifiers and 8 KiB text/translation fields. Successful stdout may contain private text and identifiers, so it must not be forwarded to logs, issues or third-party models. These interfaces establish neither publisher authenticity, media-byte integrity nor course rights.

The current compiled CLI was also exercised on a retained, operator-authorized
636,471-byte native original. All 2,455 cues matched an independent
pre-implementation whole-track oracle, including exact text, translation,
integer-millisecond timing and source order. Original bytes/length/hash, exact
selection and the independently serialized emitted-segment digest matched.
The source's empty `resource_guid` remained missing; no media association,
fresh service access or complete history was inferred. Original, oracle,
inputs and full output remain private; no new campus request was made.

## Governed native subtitle GET

`buaa recordings subtitles --online` and `--refresh` use only the reviewed fixed-origin transcript GET, with the same process-shared governor/cache policy as other adapters. Protected stdin supplies exactly one session source: `cookie`, or `session_ref` referencing a privately stored session. The request is constructed from the numeric `sub_id`; arbitrary URLs, methods and header maps are rejected. The cookie is validated as cookie pairs, marked sensitive, delivered only to the transcript target (never robots, redirects or another origin), scoped into a private cache namespace, and excluded from cache/output/report diagnostics. The subtitle command itself performs no login, automatic authentication refresh/retry, media fetch or catalog write.

Fresh HTTP status, reviewed JSON/HTML MIME labels, body budget and the raw
JSON application's success code are admitted before immutable-byte comparison.
The observed platform labels its JSON as `text/html; charset=UTF-8`; the
receipt reports that mismatch rather than silently relabeling it. Real HTML
sign-in pages and failed application codes still reject and latch. A valid
application response whose selected layout is malformed is retained privately
for a cache-only parser correction but still returns an error. The online
original hash covers the raw `{code,list}` HTTP body, not an axios/client
`{status,data}` wrapper. The supplied-import wrapper remains a distinct input
contract. A cache hit or `304` does not imply recording media retrieval.

An earlier candidate observed and revalidated one authorized 3,389-cue track
from a 595,620-byte raw response. The source's missing resource identifier
remained missing. These historical receipts do not approve later changes to
session or media transport safety; full originals and digests stay private.

## Governed classroom session

`buaa recordings session --offline` accepts the exact intent
`RESUME CLASSROOM AUTH` and arms one deliberate authentication attempt without
network I/O. It never clears request reservations, server cooldowns or unknown
outcomes. A failed attempt is not authorization to rearm automatically.
After a latched account, this explicit resume is the only way to arm another
attempt. An offline arm is not an authentication success: it neither submits a
credential nor establishes a session, and it does not by itself mean that the
account can log in.

`buaa recordings session diagnose --online` is a credential-free, read-only
report of why the reviewed login page is refused. It sends no credential and
stores no session. A clean response is not treated as credential rejection;
real challenge signals and HTTP 401/403 still latch through the shared
governor. The lease remains held through body and DOM processing. Output uses
fixed-label inspection facts and fallback/interaction reasons, never arbitrary
source names, action URLs, response URLs or field values.
The top-level `active_challenge_control` is a page observation, independent of
credential-form admission. It can be true while `form` is null and
`fallback_reason` is `login_form_not_admitted`; both read-only readers still
latch that confirmed active challenge. One bounded DOM parse supplies form
and page facts. A refused source is not a claim that no challenge exists.
This observation also applies to redirected, unexpected-URL and non-200 HTML
responses: `fallback_reason` remains `unexpected_login_response`, but an
admitted active challenge still latches and no credential form is admitted.
MIME, DOM-budget and unsupported-shadow-root refusals remain in force.
`safety_latched` reports the latch actually saved at settlement while the
shared lease is exclusive. In particular, a challenge-free HTTP 500 retains
an inspection's consumed authentication latch, while an interactive diagnosis
does not manufacture an authentication failure or latch.

A refused request names the next action instead of a generic refusal. An
unarmed attempt reports that no attempt is armed and that the explicit resume
must run first; a latched account reports the same; a cooldown or a scheduling
gap reports which interval has not elapsed.

`buaa recordings session inspect --online` is a separate, deliberate read-only
investigation. Its stdin object contains only `authorized: true` and the exact
intent `INSPECT CLASSROOM LOGIN`; credential fields are rejected. It requires
an explicitly armed authentication lease, never arms one itself, and consumes
that lease using the same pinned initial SSO URL, bounded GET redirect chain,
request spacing and Retry-After processing. No password is submitted and no
session is stored. Inspection makes no credential judgment, so it reports the
observed response instead of asserting a rejection. Clean responses do not
latch the account; actual challenges and HTTP 401/403 retain normal shared
governor handling. An
`inspected` result is not authentication success or permission to retry login.
The output reports HTTP/MIME/byte-count facts and static form analysis: the
first rejected control's fixed protocol-name label (`username`, `password`,
`type`, `execution`, `_eventId` or `submit`), `redacted` for any other present
name, or null for an absent name. Tag and input type are enumerated; required,
checked, inline-hidden/inert, own-`inert`, reviewed-protocol-value-match and
challenge-marker fields are booleans. A reviewed value match is diagnostic
only: ordinary source fields do not require a reviewed value, CSS hiding or
their own `inert` attribute. Challenge and credential-integrity gates remain
separate. Field values are never returned. Missing or
wrongly typed credential controls have separate reasons. Identifier syntax
does not make an arbitrary source-controlled name safe to print. No action URL,
execution value, Cookie, ticket or raw authentication HTML is returned. A non-admitted page
returns a `fallback_reason` with safe response metadata instead of exposing
authentication bytes. Static HTML analysis is not browser-rendered visibility.
MIME metadata uses fixed labels for recognized HTML, XHTML, JSON, plain-text
and binary types; unrecognized types are null. Arbitrary MIME subtypes or
parameters are not copied into output, even when their characters look valid.
Only explicit `text/html` permits login-form parsing. XHTML is not parsed under
HTML semantics: self-closing XML elements can change which controls are active.
Missing or other MIME types return safe response facts with
`fallback_reason: unexpected_login_content_type`, even if their body resembles
a form. The same boundary applies before any credential POST.
Potential active declarative shadow-root templates also refuse document
admission before extracting form or challenge facts. Unsupported shadow-tree
semantics are interaction-review refusals, not confirmed CAPTCHA evidence.

`buaa recordings session --online` accepts `authorized`, `username`,
`password`, the exact `LOGIN <username> classroom` intent, and
`verification` with numeric `course_id` and `sub_id`. Credentials arrive only
on protected stdin, not argv or ordinary files. The password-bearing request
is pinned to the reviewed HTTPS sign-on URL and service; redirect responses
cannot choose another credential target. Every hop remains subject to the
production governor's configured request gap and durable Retry-After policy.
Challenge signals, unreadable bodies and unsuccessful application responses
never establish a session.
Before the credential POST, collect the selected form's successful source
controls, including ordinary unknown names, text inputs, selects and textareas.
Preserve source names, values, order and duplicate noncredential names; replace
only the unique username/password values with the protected operator input.
Ordinary fields need no name/type/value allowlist, `inert` attribute or CSS
visibility exception. Do not invent protocol values, check unchecked choices,
read local files or execute page scripts. Form action and method are separate
metadata, never magic field names: source fields such as `__action` remain data
and cannot override the pinned HTTPS POST destination.
An active HTML `base[href]` requires review rather than silently resolving the
action against the response URL. The selected source submitter must not carry
`formaction`, `formmethod`, or `formenctype` overrides. Multipart and plain-text
form encodings are unsupported and refuse admission before credential POST;
default and explicit URL-encoded forms retain the existing wire encoding.
Inert template content and foreign-namespace base lookalikes do not select a
document base.
Challenge-marked controls and ambiguous credential roles still stop the flow;
interaction review is not mislabeled as a confirmed CAPTCHA. An inert hidden
CAPTCHA container alone is not an active challenge control. A later server
response is classified separately and does not imply that a password was or
was not submitted. A confirmed response challenge header remains the returned
challenge classification if MIME/body parsing fails and takes precedence over
review-only text on an HTML identity probe. Confirmed challenge classification
requires a response
challenge signal or an active, enabled challenge control anywhere on the
active page, not only inside the selected credential form. Active HTML text
matching a challenge marker can veto session admission, but does not by itself
assert an interactive challenge; script/style/template/noscript payloads are
excluded from the parsed-text veto. The same marker scan runs on the initial
login form before any password POST; inspection reports review required without
claiming an active challenge. Inspection reports
`interaction_review_required=true` and
`active_challenge_control=false` for text-only markers; no control text is
invented or returned.
The scan follows explicit HTML `form` associations, including controls outside
the form element, and does not require a control to have a `name`.
An explicit form reference resolves the first document-tree element with that
ID after parser reparenting; a non-form element blocks association with a later
same-ID form. Successful-control entries follow document-tree order after
parser reparenting; radio-group membership separately follows the final
source-checked member. Candidate selection, credential checks and field
collection share the selected form owner. Multiple matching reviewed login
submitters are ambiguous and fail closed. Challenge/interaction checks scan all
active page controls, including controls owned by another form; a second form
cannot hide an active prompt.
Forms and controls inside script/style payloads or HTML template/noscript
contents are excluded from credential role discovery and successful-field
submission. Form owners and recognized controls must be in the HTML namespace.
Foreign SVG `<form>` elements cannot own credentials; a foreign first-ID
element still blocks a later HTML form from an explicit form reference. SVG
`<template>` and `<noscript>` lookalikes do not create HTML inert subtrees, so
their HTML `foreignObject` controls remain active. Without an explicit
reference, the nearest ancestor HTML form owns a control.
Forms parsed directly inside table insertion containers (`table`, `tbody`,
`thead`, `tfoot`, `tr`, or `colgroup`) require review: the HTML parser can
associate controls outside their ancestor subtree, and the static tree sink
does not retain those associations. No missing entry is silently fabricated or
discarded. Ordinary forms inside `td` or `caption`, including their explicit
external controls, remain supported. Active Chromium iframe parsing, not
inactive DOMParser, supplies the oracle for these parser-associated owners.
Document IDs under foreign script/style remain association blockers even
though those payloads are not active prose. HTML template contents are separate
from document ID lookup; the template element itself remains a document node.
Require one username text input and one password input of the reviewed password
type. Duplicate credential names or changed credential-control types stop the
flow rather than silently choosing a credential control; ordinary fields do
not inherit or replace either credential role.
Disabled fieldsets disable their descendant controls except those inside the
fieldset's first legend. Nested fieldsets retain their own disabledness; a
later legend does not exempt a disabled credential control. Checked
checkboxes, the final source-checked radio in each owned named group, selected
options, textarea contents and the selected source login submitter contribute
their source values. A later checked disabled radio clears an earlier checked
group member but is not itself submitted. A single-select listbox larger than
one row makes no implicit choice; ordinary one-row selects retain their source
values. Disabled, unchecked and nonselected controls do not contribute values.
Options in script/style payloads or HTML template/noscript descendants do not
create selected values or authorize a nonempty execution token; option-text
fallback omits those inert payloads. The submit wire body normalizes CR, LF and
CRLF in every successful field name and value to CRLF before url-encoding.

An implicit wrapping-label association selects the first live HTML labelable
descendant; HTML-inert template descendants cannot steal the association, while
ordinary disabled, hidden or `inert`-attribute controls retain their native
position in the search order. Successful controls with a nonempty `dirname`
append its direction entry immediately after the primary value. Direction is
resolved from explicit/inherited `dir` state or the first Unicode Bidi_Class
`L`, `AL` or `R` value for `dir="auto"`; the telephone state defaults to LTR
when `dir` is absent. Companion names and values count against the same field
and byte budgets. A companion named `username` or `password` requires explicit
interaction review and cannot replace protected credentials.
Contained-text directionality includes noscript text, unlike the intentional
noscript exclusion in challenge and source-prose scanning.
Initial input values retain browser submission semantics instead of blindly
copying the `value` attribute: text/email/URL line-break normalization, email
trimming, URL whitespace trimming, number/date/time invalid-value sanitization,
datetime-local canonicalization, range defaults/clamping/decimal step-base
rounding with positive-direction ties and canonical value serialization, and
CSS color names and hex, RGB/HSL/HWB, Lab/LCH, OKLab/OKLCH, and the supported
`color()` spaces (sRGB, sRGB-linear, Display-P3, A98 RGB, ProPhoto RGB, Rec. 2020
and XYZ D50/D65) are covered by source fixtures. Textarea line endings are
normalized to CRLF.
Modern HSL/HWB numeric channels use percentage-reference units; legacy comma
HSL still requires percentages. HWB normalization retains the original
non-negative white/black ratio above 100%. HSL retains the upper clipping
observed in actual Chromium FormData. A named successful, nonempty textarea
with `wrap="hard"` requires interaction review: rendered widths can produce
different submission breaks for identical `cols` and source text. The static
reader neither guesses these breaks nor forwards the unwrapped value. Empty
hard-wrap textareas remain layout-independent; disabled controls stay excluded.
Range step calculations retain the default midpoint in decimal arithmetic and
compute local decimal quotient/remainder without scaling a distant bound.
Candidates undergo one binary64 conversion; overflow-safe local/global
arithmetic remains available for values outside the bounded decimal domain. If no
bounded candidate can be computed, login-form parsing refuses instead of
forwarding an unaligned source value. Chromium range FormData serialization
uses the locally observed 15-significant-digit boundary independently of the
step calculation.
Hidden-control values retain source line breaks, except ASCII-case-insensitive
`_charset_` entries, whose value is the serializer's UTF-8 encoding name.
RGB/HSL/color-space functions
have CSS comments removed before channel/alpha parsing, must contain exactly
three channels and an optional valid alpha, and reject malformed extra
components to the browser's default color value. Comment token boundaries do
not manufacture the actual whitespace required around binary math `+` and `-`.
Dimensional `round` arguments require an explicit same-unit interval; numeric
arguments retain the default interval. Aligned values and negative zero survive
nearest rounding, and a zero `mod` result takes the divisor's sign.
Number trailing-dot
values and time values with an empty or overlong fractional part are sanitized
to empty.
An isolated Chromium `FormData` oracle confirmed these expected values. It also
confirmed that datalist descendant controls are included in its form entries;
they remain source-forwarded rather than being filtered by a stricter but
incorrect assumption.
Existing protocol fields, including `type`,
`execution` and `_eventId`, use this same source-forwarding contract rather
than a special inert-text exception. A nonempty execution token and unique,
correctly typed credential roles remain required before any password POST.
Challenge-marked buttons and submit/button/reset inputs cannot evade both
refusal gates through malformed, conflicting or stylesheet-overridden CSS.
Without structural inertness, uncertain visibility requires operator review.
Associated `label[for]` and wrapping-label active text, button text (including
split inline nodes), and submit/button/reset value labels are also checked
transiently for supported challenge markers, ignoring Unicode
whitespace consistently in both representations without copying input values.
Label-only matches
require interaction review, not a claim that CAPTCHA was independently confirmed;
neither label text nor input values enter the diagnostic metadata.
The same review-only rule applies to `aria-label`, `placeholder` and `title`
cue text; these attributes alone never confirm an active challenge.
An active `autocomplete="one-time-code"` cue likewise requires operator review
without being classified as a confirmed CAPTCHA. Hidden inputs are not treated
as interactive OTP prompts.

After the credential POST, scan all final-response controls and associated
labels independently of the original credential/execution form. A secondary
challenge must stop the flow even when that form has disappeared; a normal
application page need not contain any login form. Password-bearing controls
outside structurally inert content, including disabled or unnamed password
inputs, still veto session admission independently of submission eligibility.
A final-response analysis error stops and settles the attempt instead of being
treated as an empty, challenge-free page. This scan does not build a second
submission payload or apply the login payload's field-count limit to the app.
When the fresh lesson probe is labeled HTML, it receives the same
interaction/password scan before lesson IDs can admit a session. XHTML is
refused as unsupported; the declared JSON MIME path is not reinterpreted as
embedded HTML.
Text-only response evidence matching any supported challenge marker also vetoes
admission, including `校验码`; text alone never confirms an active control.
The final/probe DOM's shared active-text walk also catches markers split across
inline elements. This produces `UnsafeInteraction`/review-only refusal, not a
confirmed `Challenge`; script/style/template/noscript payloads are excluded.

The positive confirmation is a fresh, explicitly selected lesson response
with matching selectors and no explicitly conflicting tenant, not independent proof of account identity or course
rights. Only then may an owner-only session be atomically stored and its
reference returned. Session and failure artifacts remain private, and the
command does not perform automatic authentication refresh or retries.
Successful output retains the `session.cookie_names` array shape but emits only
the fixed `redacted` label for each applicable cookie. Original cookie names
and values remain only in protected session state and actual request headers;
they are not ordinary diagnostic metadata.

The private version-3 session file preserves each classroom cookie's acquired
host/domain scope, host-only/domain declaration, Path, Secure/HttpOnly flags
and absolute expiry. A cookie whose declared domain lies outside the reviewed
platform family keeps that canonical declared domain as its identity while
delivery stays narrowed to the setting host. Single sign-on cookies are
excluded. The `__Secure-`,
`__Host-`, `__Http-` and `__Host-Http-` prefixes are admitted only with their
required Secure/HttpOnly, host-only and explicitly declared `Path=/`
properties; stored snapshots are revalidated before use. Quoted cookie values
retain their exact quotes.
Each subtitle or lesson-source request filters that snapshot for its own URL
and the current time; a cookie usable by the verification endpoint need not be
usable by another API. A request with no applicable unexpired cookie stops
locally. Legacy flattened files cannot recover these restrictions and are
rejected until a new deliberate authentication succeeds; no scope or lifetime
is invented. Stored expiry also reaches the transport: after robots processing
and governor acquisition, an expired credential stops before transmission and
the unused lease is finished without clearing safety history.
An explicitly supplied `cookie` remains operator-scoped input,
not a reconstructed stored-session snapshot.
Cookie values retain the bounded RFC 6265 cookie-octet grammar, which already
permits colons and slashes in URL-shaped values. Such values are not evidence
of a rejected cookie and do not establish the cause of a callback HTTP 500.
Paired surrounding quotes are preserved; embedded quotes, separators, spaces,
backslashes and control characters remain refused.
Cookie Max-Age takes precedence over Expires regardless of attribute order,
including deletion declarations with an empty value and invalid Expires.
A valid empty cookie value replaces the previous same-name/domain/Path value;
it remains empty in request headers and private storage rather than reviving
the old token. An empty value alone is not a deletion declaration.
Host-only versus Domain scope controls reach, not cookie identity: for the same
effective domain, either declaration replaces or deletes the other. Loaded
private snapshots with duplicate identities or noncanonical domain spelling
are refused rather than guessing which token is current.
A declared domain outside the reviewed platform family is narrowed to the
setting host for delivery while its canonical declaration remains the cookie
identity, so a later deletion of that declared identity does not remove a
distinct host-only cookie. Earlier session files cannot recover the original
declared identity and are refused until a new deliberate authentication
succeeds; no identity is invented and no session is restored automatically.
Outgoing headers order applicable cookies by descending Path length and retain
creation order for equal-length paths. Replacing an existing identity updates
its value in place; private serialization preserves that creation order.
A syntactically valid negative decimal Max-Age expires immediately even when
its magnitude exceeds machine integer ranges. Positive lifetimes remain bounded;
malformed decimal syntax and over-cap lifetimes do not replace an existing cookie.
Expires uses the [RFC 6265 cookie-date algorithm](https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1),
not only RFC 2822 dates, so valid asctime-style expiry deletions are honored.
Attempt receipts retain only fixed allowlisted route labels; unknown redirect
paths, including matrix-parameter session identifiers, become `<unknown-route>`.
Query-name metadata likewise retains only the fixed `ticket` label; unknown or
encoded keys and bare query tokens become `<unknown-query-name>`, never copied
or decoded into receipt data.

## Source-declared recording media

`buaa recordings media --online` selects numeric `course_id` and `sub_id`
through `selection` with fixed tenant `21`, authorization and exactly one of
`cookie` or `session_ref`. Lesson-source responses use the existing private
session-scoped, cache-first classroom client. The selected source must declare
the exact admitted HTTPS recording URL; no caller URL, redirect or filename
guess authorizes a download. The classroom Cookie is never sent to the media
host.

`fetch:"head"` is a bounded zero-based prefix: the returned range, total size
and actual bytes must match the requested `byte_budget`. It is not a whole-file
digest. `fetch:"full"` requires an explicit private 0700 `private_dir` and
complete admitted MP4 bytes within the budget. Exclusive 0600 staging and an
atomic completion receipt keep partial responses out of the playable output.
Existing completed local media may be reused only after full length/hash
verification; file presence or an ETag is not verification.
Successful full and prefix responses retain server Retry-After instructions in
the same shared governor before body processing, just as rejected responses do.

Any `native_track` facts on input remain operator assertions. Platform
lesson selectors, recording metadata and a full media digest establish their
own provenance, but date/duration agreement cannot recover a native track's
missing resource identity or prove rendered synchronization. A replay entry
marked `course_live` is not an ongoing live stream. No live playlist, key
scheduling, automatic reconnect, attendance or completion behavior is implied.
Read-only historical source recovery found finite MP4 replay acquisition, not
an ongoing-live contract. The inspected finite-HLS collector requires
`EXT-X-ENDLIST` and refuses encryption and byte-range playlists; it is not a
governed live scheduler. No localhost helper or challenge bypass is required
by the recovered normal replay path. Live implementation still needs a genuine
ongoing source observation after safe session admission, preserving the existing
account-wide request/background floors and lease through body processing.

## Bounded local replay

`buaa recordings replay` launches installed mpv or VLC directly, without a
shell. Input is strict JSON on stdin with `authorized: true`, `player`, and
`media.path` selecting an existing absolute local file. Remote URLs remain
unsupported: the public-page transport is not a generic media fetch profile.
The local path, subtitle text and source URLs are not included in receipts.
The player child is confined against Internet socket creation; a local
playlist is not permission for the player to fetch remote segments or keys.
Unix sockets remain available for local display/audio IPC. This is a network
boundary, not a general sandbox against an adversarial media decoder or
local filesystem access. Player configuration and helper/script autoload are
disabled so external configuration cannot enable daemon playback.
The confinement requires Linux x86-64; unsupported platforms fail closed.

Optional `seek_seconds` selects the initial media position. `max_seconds`
limits the player run (default 120, maximum 3600); the parent stops and reaps
the child when the bound expires. Media hashing precedes this player bound.
Normal audio/video output is the default; explicit `headless: true` requests
null/dummy outputs and does not establish audible or visible device output.

`subtitles.path` selects an existing SRT/VTT file, or `subtitles.segments`
selects normalized integer-millisecond cues. Segment materialization requires
an explicit private `private_dir` owned by the caller with mode 0700. The
temporary SRT is mode 0600, exclusively created and cleaned after the player
exits. Native JSON cue preservation and player-format representability are
different contracts; unrepresentable exports are refused rather than silently
dropping text or changing timing.

Receipts distinguish submitted player arguments/subtitles, the observed
process exit, and unverified rendering/audio facts. Successful process launch
alone is not subtitle-rendering or synchronization proof.

A separate bounded real-media mpv/X11 observation exercised an exact seek,
playback clock advancement and subtitle pixels in a virtual display. The
same paused source frame was captured both with subtitles and video-only;
pixel differences were localized to the subtitle region. This proves that
selected local derived cues can render on the observed player, not that the
ASR text is accurate, that source media and native classroom tracks are
universally associated, or that physical speakers were heard. Private frames,
source text, media identifiers and full source digests remain outside Git.

A separate VLC/X11 observation showed subtitle glyphs over video in a full
native-window capture, alongside seek and clock observations. The first
virtual desktop was smaller than the native window and clipped the subtitle
region, so those early captures could not establish subtitle absence. A
subtitle toggle while paused left the captured pixels unchanged; that control
is inconclusive, not evidence of removal or general synchronization.

## Live playback and remaining subtitle service gaps

Live playback, current audio/video, reconnect/stop lifecycle and governed
playlist/fragment/key/range scheduling remain unimplemented. Local replay and
the observed derived subtitle track do not complete live updates, whole
native-track/media binding or all-player synchronization acceptance. The
whole supplied-native-track import proof above is a separate input-processing
result, not proof that its missing media association has been recovered.

## Object-storage interface facts — source-only draft

Authorized, authenticated repository reads pinned the Life source to `af59427c7f6bac3382b5989b811b69872f4de928`. A structural Python AST inspection, not execution of the private implementation, found S3-compatible `HeadObject(Bucket, Key)` and `GetObject(Bucket, Key)` operations. The read inspector delegates to existence and digest helpers; the digest helper streams `Body` in 262,144-byte chunks, computes SHA-256 and closes the stream in a `finally` block. The same source also contains a `PutObject` operation in a separate workflow; it is explicitly excluded from this proposed read-only integration. No source code, operational default, endpoint, credential configuration, catalog row or media bytes were copied into this project.

These are interface facts, **not an owner-approved contract or working buaa-cli remote adapter**. No private helper was run and no object-store request occurred. Repository read permission does not authorize bucket enumeration, object downloads, publishing course materials, or executing the upstream upload/remote-task tooling.

Owner review and the private operational prerequisites are tracked in [issue #74](https://github.com/cyjin-yl/buaa-cli/issues/74). Keep endpoints, credentials and private inventory out of public comments.

The existing consumer provides declared `bucket`, `object_key`, `sha256` and `bytes` for each original/derived descriptor. A future authorized read must select an exact object under a rights-cleared inventory, retain the process-shared governor through bounded body hashing/private cache persistence, compare both observed SHA-256 and byte length with that declaration, and keep original and derived receipts separate. `HeadObject` existence, ETag, or a catalog hash alone must not be reported as verified object bytes. Ingestion time must not become capture time; unresolved ancestry must remain unresolved. No automatic retries, auth refresh, independent worktree limiter or batch parallelism may be inherited from private tooling.

Implementation prerequisites remain: owner approval of a narrowly scoped HTTPS read/authentication/immutability contract; an explicit allowlist and maximum byte budget; an authorized object inventory with rights for the original and permitted derived use; private stdin/keyring credential delivery; and synthetic streaming/error fixtures. None of the operational values belongs in public fixtures or diagnostics. Shared governor timing, Retry-After, rejection/challenge latches and deliberate authentication resume remain mandatory. Issue [#47](https://github.com/cyjin-yl/buaa-cli/issues/47) separately tracks the missing classroom-replay source/rights contract; storage interface inspection does not close it.

## Read-only and resource limits

The catalog must already exist and have the supported table/column/key/FTS mapping. Missing, unsupported or malformed data is not replaced with an empty success or a new database. The reader disables URI options and extension loading, opens read-only, uses query-only/defensive settings, and bounds SQLite execution, busy waiting, metadata and text sizes.

Segment text is bounded to 1 MiB per row and 8 MiB across the selected page (including the extra pagination row). Oversized pages fail as a whole with reduce-page-size guidance; they are not silently truncated. Metadata fields and schema declarations are separately bounded. SQLite WAL readers can create/update coordination sidecars when the filesystem permits; no catalog/schema data or journal mode is changed. Supply a local filesystem catalog; the command uses no network client, but it is not a sandbox for arbitrary filesystem drivers.

No original object or private Life database was used for development proof. Tests use synthetic SQLite catalogs; no real campus or object-store operation is authorized by this implementation work.
