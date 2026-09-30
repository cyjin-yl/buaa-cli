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
