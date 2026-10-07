# Historical archive lookup

The archive adapter targets the documented Internet Archive CDX API and Wayback identity replay. It does not contact the original campus host, authenticate to a campus service, save pages to the archive, or reconstruct missing history. The default is local cache only. Synthetic/loopback proof remains separate from the bounded live homepage observations recorded below; general service availability and complete history are not implied.

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

Lookup timestamps use complete UTC civil times (`YYYYMMDDhhmmss`), with inclusive `from`/`to` bounds. The default page limit is 100, maximum 1000. Pass `next_cursor` back as `cursor` without editing or decoding it. The adapter encodes the documented CDX continuation token once as a single query parameter. A cursor is bound to the exact query (url, from, to, limit) that minted it: presenting it under any other scope, or presenting a cursor the adapter never issued, is rejected before a request. Wildcard/domain crawls are not supported by this command.

`urlkey` is requested and validated as internal CDX state but remains absent from public results. Internet Archive's [upstream resumption-key report](https://github.com/internetarchive/wayback/issues/121) demonstrates that omitting `urlkey` can make a continuation skip captures; this client therefore includes the canonical field and still passes the server-provided cursor through unchanged.

## What the evidence means

A lookup returns archive-reported capture timestamp, original URL, MIME type, HTTP status, digest and archive-record length. The archive-reported digest is **not** represented as a locally verified resource hash. Record length is not claimed to be the original resource's byte length. The CDX response itself has a separately verified SHA-256 and retrieval metadata.

Capture replies retain the exact replay bytes as `immutable_original.body_base64`, with SHA-256 and byte length. `Memento-Datetime` must match the requested timestamp and the `original` Link relation must identify the requested original. Redirects or nearest-capture substitutions do not become exact successes. An unattributed 404/410 is a query-scoped gap; an attributed 4xx/5xx preserves the archive-reported resource status.

Capture time is **not publication time**. Publication date remains null with `confidence: unknown`; this adapter does not infer a date from a path, title, capture timestamp or HTTP Last-Modified. Original and retrieved URLs, HTTP facts, cache state and revalidation facts remain distinguishable. A local hash verifies retrieved bytes, not the archive's authenticity.

Empty results mean only `missing_in_query_scope`. They never assert complete historical coverage. A continuation cursor indicates more index results; missing pages or archive gaps remain missing. Raw HTML/media is not interpreted as instructions or executed by this tool.

## Safety and private cache

Only approved HTTPS `web.archive.org` routes are allowed. TLS validation is enabled; redirects, proxies, cookies and automatic HTTP retries are disabled. Before a network target request, a robots policy is checked with a cache age of at most 24 hours. Denials and unavailable policy are not bypassed.

Robots and target requests use the same process-shared governor. Its lease spans response handling and cache persistence; only one request is in flight, with at least five seconds after completion. A bounded local wait may precede a request; network failures are not retried. Current-source Retry-After and 429 cooldowns persist. For capture responses, exact Memento date/original attribution classifies 4xx/5xx as archived-resource status before current-source latch/cooldown policy; archived 401/403/429 and their Retry-After do not affect the safety latch or cooldown state. A challenge-free, body-complete attributed response counts as a successful network interaction for the consecutive-failure counter. A reliable `CF-Mitigated: challenge` signal remains authoritative. No CLI unlock/reset path is introduced.

Cache files are private beneath the effective user's passwd home, not the source tree or a per-worktree directory. Cached bodies are hash-checked before use. Immutable capture bytes are never silently overwritten on conflict. Keep private cache and account governor history out of public Git; never delete governor state to regain throughput.

Public CLI error categories include invalid_input (2), unsupported (3), auth_latched (4), permission (5), unavailable (7), rate_limited (8), conflict (9), and unknown_outcome (9). `unknown_outcome` is specific to a logout request that may have been applied but lacks a reliable receipt; retries and new commits for that account remain blocked until typed offline operator resolution. A transport error is not proof that a historical page never existed.

## Bounded live proof

[Issue #82 operational receipt](https://github.com/cyjin-yl/buaa-cli/issues/82#issuecomment-5952491700) records the actual merged CLI observations on 2026-10-02. The first capture invocation refreshed robots as HTTP 404 and exited 8 before the target because the retained 60-second interval exceeded the 30-second bounded wait. After independently checking fresh robots and the full shared deadline, one deliberate exact replay succeeded; there was no retry loop or policy relaxation.

- Original: `http://www.buaa.edu.cn:80/`; exact timestamp `19970416014726`.
- Replay: `https://web.archive.org/web/19970416014726id_/http://www.buaa.edu.cn:80/`, HTTP 200 `text/html`, matching `Memento-Datetime: Wed, 16 Apr 1997 01:47:26 GMT` and original Link.
- Original bytes: 3,758; SHA-256 `4cf418189fb99ac5cf2873673337b3722d7e42e60e38ad633ceb706e7c6fb05d`; fetched at `1790944036626`. Independent base64 decode/size/hash verification and actual cache-only replay matched the bytes and identity.
- Dated CDX query: `https://www.buaa.edu.cn/`, inclusive `19970101000000`–`19971231235959`, limit 10. Returned timestamps `19970416014726` and `19971210122410`; 327 response bytes, SHA-256 `7d942e8e87eb0864e73697d69b2f368e528343a56b12ec945e53a723573271cc`, fetched at `1790944266753`. Actual offline replay matched hash/captures.

`more_results=false` applies only to that returned index page; `complete_history=false` remains explicit. CDX rows retain null resource hashes: the second capture's resource was not fetched. Publication date stays null/unknown despite origin Date/Last-Modified headers. This proves one exact homepage replay, not archived announcement parsing, all-college coverage, archive authenticity or publisher signatures. No direct original-host request, authentication, mutation, nearest-capture substitution or bypass occurred. Earlier failed-replay evidence is preserved.

## Exact Materials-board index observation

The existing native client separately queried only `http://mse.buaa.edu.cn/xwdt/gggs.htm`, exact match, limit2 and no date bounds/cursor. Its first online invocation refreshed expired robots as404, then correctly exited8 before index HTTP under the retained60-second gap/30-second bounded wait. After normal shared pacing, the first actual index request returned HTTP200 JSON:3 original bytes, SHA-256 `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`, fetched at1791390335997, zero captures/no cursor and `missing_in_query_scope`. Actual offline reuse retained the same hash/fetch facts and empty records without another request. [Detailed scoped evidence](STATUS.md#exact-materials-archive-index-scope).

This is a real exact-query gap, not a guessed historical page, all-URL/era absence or archive outage. No capture timestamp/original can be produced from an empty index; capture and historical interpretation remain blocked for this source scope. No direct campus-HTTP access, protocol/host/nearest-capture substitution, network retry loop or governor relaxation occurred. Current-original parser compatibility and synthetic1997 fixtures remain distinct from this archive observation.

## Source-declared Materials root and PHP notice

Separate exact root and source-declared PHP queries now have real bounded observations. They **do not replace** the zero-capture modern-board gap above. Each index returned two rows plus an unfollowed cursor; second resources remain unfetched and `complete_history:false` remains authoritative.

| Exact original / selected capture | Verified original bytes / SHA-256 | Index facts |
| --- | --- | --- |
| `http://mse.buaa.edu.cn:80/` / `20040326165604` |20,018 / `de230099e658ed1e28af08be00676bed86a99aa166f31189c6e2e50567d68a0f` | Query `http://mse.buaa.edu.cn/`, limit2;397 bytes, SHA-256 `bfd0f6b92788dbd0363719b869b785ab01ecb6139308dd2c6c1662cc0bd1366d`; second20040606020824 |
| `http://mse.buaa.edu.cn:80/call_board_detail.php?call_board_id=11` / `20040409111518` |3,684 / `8677e0934e149e6dee81c0b3e28268eb97a5bc656b02445d206c182fba7180d1` | Exact PHP URL, limit2;590 bytes, SHA-256 `0bd90047f589f20e9de19856cb691765dc3fe06480d10df05b84f1461985b031`; second20040811030013 |

Both exact replays returned HTTP200 with matching Memento date/original identity. Independent base64/private-cache/size/hash checks and actual offline replays preserve the entire immutable original, exact URL/capture and original fetch time. Index record lengths5183/1941 are not resource byte lengths; CDX resource hashes remain null/unverified. The root and notice are different capture epochs, not proof of a same-epoch board, publication date or source authenticity. A private non-executing root/helper inspection bound the selected notice URI; no direct campus PHP request, inferred ID, JavaScript execution, alias or nearest-capture substitution.

The local offline `announcements history` article path now interprets the retained PHP template only with explicit `encoding:"gb2312"` and its matching source charset declaration. **Supply the raw original base64, not transcoded UTF-8**: retrieval binds raw bytes; interpretation separately hashes decoded UTF-8. Its ordered title/body/footer privately match the source, without invented paragraphs/grid. The unlabelled footer date is retained with unverified role and `published_at:null`; capture time cannot substitute. Supplied provenance remains operator-asserted because this import receives no Memento headers. The archive adapter itself does not extract announcement text or grant live PHP fetch permission.

The preceding source-acquisition chain used six governed archive GETs, including robots and the empty modern-board query; this new interpretation issues none. Existing governor floors/history/latches remain intact. Unreviewed local stack, not root-main/Pages integration, all-college history or an authenticity certificate. [Exact source/native proof and boundaries](STATUS.md#materials-archived-php-notice-text).

The supplied GB2312 **root** now has an offline `announcements history` listing interpreter: exact HTTP root with optional literal `:80`, explicit encoding and default/explicit listing kind. All seven original PHP notice declarations at active-anchor ordinals27–33 and the document title privately match the complete original. Earlier two bindings were selected examples only. Keep `href:#` separate from declared target/resolved URL; a bounded source helper is not JS execution, runtime navigation or fetch permission. Other popup namespaces are excluded, dates/publisher remain unknown, raw/derived hashes stay separate and `complete_history:false`. March26 root does not establish the separately captured April9 notice state or fill missing modern-board history. No new GET. [Complete original/native comparison](STATUS.md#materials-archived-root-notice-listing).

## Second source-declared Materials notice original

The retained March26 root separately declares `http://mse.buaa.edu.cn:80/call_board_detail.php?call_board_id=6` at active-anchor ordinal32. Its new exact limit2 index returned HTTP200:585 bytes, SHA-256 `f9afb5ba4bd2c35beb6ad5cb6d45048a4ab9db46b305c9530faade22e93505b0`; captures20040409113345 and20040606225745 plus an unfollowed cursor. The latter resource remains unfetched. Record length1060 is not resource byte length, and the CDX digest is unverified against retrieved bytes.

Only the first exact capture was retrieved: matching Memento date/original Link, HTTP200,1,878 original bytes, SHA-256 `d4e75b9e5b711a96ec3c3f3ef509e142ad69fcfe5f1a5138f954bfeae54226c7`. Independent base64/cache/size/hash checks and actual offline reuse preserved whole bytes, identity and fetch time. The unchanged family parser's explicit raw-GB2312 article import privately matched the entire ordered title/body/footer, without invented paragraphs/grid. Separately decoded UTF-8:2,108 bytes, SHA-256 `2448561cce981b6bc7b37de1e99c118d96164af0d9e7eb1f2162723801838385`. Footer2004-02-19 remains role-unverified; publication/publisher remain unknown. RootMarch26/articleApril9 are not the same capture epoch, and an operator-asserted import is distinct from observed archive headers.

Two new GETs/eight total in this Materials chain; same permanent governor, no retry/policy relaxation/direct campus request/authentication/write. Offline proof left its post-capture bytes unchanged. This evidence does not replace the empty exact modern-board query, follow other root declarations/cursors, certify authenticity or establish complete history. No Rust change/new build/test/review/approval/root-main integration or compiled-discovery claim. [Complete bounded native proof and remaining gaps](STATUS.md#materials-second-source-declared-archived-notice).

## Contract sources

- [Internet Archive CDX API](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md): named JSON columns, exact URL scope, inclusive date ranges and resume keys. No API key cookie or restricted field is requested.
- [RFC 7089](https://www.rfc-editor.org/rfc/rfc7089): Memento-Datetime and original-link provenance, and the limits of archive trust.

This adapter does not implement a general Memento TimeGate/TimeMap crawler, college discovery, announcement text extraction, Life storage integration or transcript search. Those remain separate acceptance items rather than implied capabilities of an archive index client.
