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

`buaa recordings subtitles --online` and `--refresh` use only the reviewed fixed-origin transcript GET, with a protected-stdin existing session and the same process-shared governor/cache policy as other adapters. The request is constructed from the numeric `sub_id`; arbitrary URLs, methods and header maps are rejected. The cookie is validated as cookie pairs, marked sensitive, delivered only to the transcript target (never robots, redirects or another origin), scoped into a private cache namespace, and excluded from cache/output/report diagnostics. There is no password/master-key input, login, refresh, redirect following, automatic retry, media fetch or catalog write.

Fresh HTTP status, JSON MIME, body budget and application success are admitted before immutable-byte comparison. An indeterminate/denied/redirected session latches the shared safety outcome and does not replace a retained original. A valid application response whose selected layout is malformed is retained privately for a cache-only parser correction but still returns an error. The online original hash covers the raw HTTP body, not a constructed wrapper; a cache hit or `304` does not imply recording media retrieval. The current source/runtime gate remains pending parent validation, and no accepted authenticated target response is claimed here.

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
