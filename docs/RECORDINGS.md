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

Input is JSON on stdin, output is one JSON object on stdout, and errors are sanitized JSON on stderr. `buaa schema` exposes exact input/output schemas. Optional `asset_id` restricts matches to that exact segment-owning asset. Limits are 1–100 hits (default 20). The literal phrase uses the catalog's `unicode61` tokenizer and searches text, not speaker names. It is not an arbitrary substring search; quotation marks and query-language operators in input do not become executable FTS/SQL syntax.

Replies contain segment text, its UTF-8 SHA-256, timing, and provenance keyed by segment-owning asset ID. The segment-text hash verifies only retrieved text, not the original media or the entire transcript asset. The raw query and local catalog path are not echoed; query and catalog identity bindings are reported instead.

Pass `next_cursor` unchanged as `cursor` to obtain the next page. It binds the normalized phrase, exact asset filter and catalog identity. The identity hashes canonical path/device/inode; it is **not a content hash or authorization token**. Results are ordered by increasing segment ID. One read transaction makes a request internally consistent, but a changing catalog is not frozen across separate pages; that limitation is explicit in every reply.

## Original and derived provenance

The reviewed tables are `asset`, `asset_relation`, `transcript_segment` and the external-content FTS5 index `transcript_fts(text, speaker)`, backed by `transcript_segment.id`. Asset descriptors retain ID, kind, bucket/key, recorded SHA-256 and size, MIME type, capture/ingestion facts, source, language and privacy. Arbitrary `metadata_json`, tags, ingest-event details and credential configuration are not read.

Only outgoing `transcript_of` and `derived_from` relations are ancestry links. Terminal audio/video assets are catalog-reported original candidates; they stay separate from the segment-owning transcript/derived asset. Multiple originals are returned explicitly. Alternate/superseding/manifest relations are not silently reinterpreted as ancestry.

Resolution is bounded to 16 ancestry hops, 64 loaded asset IDs and 128 retained edges. Missing assets, cycles, non-original terminals and resource limits produce explicit issues and incomplete provenance. A shared ancestor in a diamond is not a cycle. Dangling targets do not acquire fabricated hashes. Missing capture and segment timing remain null; ingestion time never substitutes for capture time.

`hash_verification` is always `catalog_declared_not_blob_verified`. Bucket/key fields are catalog locators, not proof that an object was fetched or exists. This command does not verify or disclose object-store credentials and does not reconstruct missing originals or history.

## Read-only and resource limits

The catalog must already exist and have the supported table/column/key/FTS mapping. Missing, unsupported or malformed data is not replaced with an empty success or a new database. The reader disables URI options and extension loading, opens read-only, uses query-only/defensive settings, and bounds SQLite execution, busy waiting, metadata and text sizes.

Segment text is bounded to 1 MiB per row and 8 MiB across the selected page (including the extra pagination row). Oversized pages fail as a whole with reduce-page-size guidance; they are not silently truncated. Metadata fields and schema declarations are separately bounded. SQLite WAL readers can create/update coordination sidecars when the filesystem permits; no catalog/schema data or journal mode is changed. Supply a local filesystem catalog; the command uses no network client, but it is not a sandbox for arbitrary filesystem drivers.

No original object or private Life database was used for development proof. Tests use synthetic SQLite catalogs; no real campus or object-store operation is authorized by this implementation work.
