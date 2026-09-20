# Historical archive lookup

The archive adapter targets the documented Internet Archive CDX API and Wayback identity replay. It does not contact the original campus host, authenticate to a campus service, save pages to the archive, or reconstruct missing history. The default is local cache only. Implementation verification uses synthetic protocol data and an isolated loopback HTTP server; live Internet Archive availability is not implied.

## Commands

Requests are JSON on stdin; replies are one JSON object on stdout. Inspect `buaa schema` for exact input/output schemas. Invalid input and transport diagnostics use sanitized JSON on stderr.

```sh
# Read a previously cached exact-URL index query. This example URL is synthetic.
printf '%s\n' '{"url":"https://college.example/notice/42.html","limit":100}' \
  | buaa archive lookup

# Explicitly permit read-only archive access on a cache miss.
# Replace the synthetic URL only with an original you are authorized to access.
printf '%s\n' '{"url":"https://college.example/notice/42.html","from":"20200101000000","to":"20201231235959","limit":100}' \
  | buaa archive lookup --online

# Retrieve exactly the requested archived state, not the closest available state.
printf '%s\n' '{"url":"https://college.example/notice/42.html","timestamp":"20200102123456"}' \
  | buaa archive capture --online
```

`--online` is cache-first. `--refresh` explicitly revalidates cached data using ETag/Last-Modified when available. The two switches are mutually exclusive. Neither grants access to restricted records or permits authentication retries. Offline misses return unavailable, not an empty history. Query input is bounded to 32 KiB; original URLs and cursors also have explicit limits in the schema. HTTP bodies are bounded to 8 MiB.

Lookup timestamps use complete UTC civil times (`YYYYMMDDhhmmss`), with inclusive `from`/`to` bounds. The default page limit is 100, maximum 1000. Pass `next_cursor` back as `cursor` without editing or decoding it. The adapter encodes the documented CDX continuation token once as a single query parameter. Wildcard/domain crawls are not supported by this command.

## What the evidence means

A lookup returns archive-reported capture timestamp, original URL, MIME type, HTTP status, digest and archive-record length. The archive-reported digest is **not** represented as a locally verified resource hash. Record length is not claimed to be the original resource's byte length. The CDX response itself has a separately verified SHA-256 and retrieval metadata.

Capture replies retain the exact replay bytes as `immutable_original.body_base64`, with SHA-256 and byte length. `Memento-Datetime` must match the requested timestamp and the `original` Link relation must identify the requested original. Redirects or nearest-capture substitutions do not become exact successes. A missing 404/410 response is distinguished from a genuine archived error response with Memento attribution.

Capture time is **not publication time**. Publication date remains null with `confidence: unknown`; this adapter does not infer a date from a path, title, capture timestamp or HTTP Last-Modified. Original and retrieved URLs, HTTP facts, cache state and revalidation facts remain distinguishable. A local hash verifies retrieved bytes, not the archive's authenticity.

Empty results mean only `missing_in_query_scope`. They never assert complete historical coverage. A continuation cursor indicates more index results; missing pages or archive gaps remain missing. Raw HTML/media is not interpreted as instructions or executed by this tool.

## Safety and private cache

Only approved HTTPS `web.archive.org` routes are allowed. TLS validation is enabled; redirects, proxies, cookies and automatic HTTP retries are disabled. Before a network target request, a robots policy is checked with a cache age of at most 24 hours. Denials and unavailable policy are not bypassed.

Robots and target requests use the same process-shared governor. Its lease spans response handling and cache persistence; only one request is in flight, with at least five seconds after completion. A bounded local wait may precede a request; network failures are not retried. Retry-After and 429 cooldowns persist. Authentication rejection or a reliable challenge signal latches access. No CLI unlock/reset path is introduced.

Cache files are private beneath the effective user's passwd home, not the source tree or a per-worktree directory. Cached bodies are hash-checked before use. Immutable capture bytes are never silently overwritten on conflict. Keep private cache and account governor history out of public Git; never delete governor state to regain throughput.

Public CLI error categories include invalid_input (2), unsupported (3), auth_latched (4), permission (5), unavailable (7), rate_limited (8), and conflict (9). A transport error is not proof that a historical page never existed.

## Contract sources

- [Internet Archive CDX API](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md): named JSON columns, exact URL scope, inclusive date ranges and resume keys. No API key cookie or restricted field is requested.
- [RFC 7089](https://www.rfc-editor.org/rfc/rfc7089): Memento-Datetime and original-link provenance, and the limits of archive trust.

This adapter does not implement a general Memento TimeGate/TimeMap crawler, college discovery, announcement text extraction, Life storage integration or transcript search. Those remain separate acceptance items rather than implied capabilities of an archive index client.
