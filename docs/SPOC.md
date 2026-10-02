# SPOC public surface — contract draft

**Status: PENDING OWNER REVIEW.** This is contract *evidence and a draft*, not an
approved service contract. It authorizes no authenticated read, no course
inventory, and no course/media download. The SPOC acceptance item stays **blocked** until an
owner reviews this contract and supplies a rights-cleared course inventory.

`buaa spoc surface` and `buaa spoc script` are read-only contract tooling, not
authenticated adapters. They observe fixed public pages and one explicitly
selected, source-declared public script through the same shared governor and
private cache. Output contains only HTTP/MIME/size/hash/retrieval facts, title,
form shape and safe external script declarations. Raw HTML/JavaScript, input
names/values and source configuration never enter stdout, logs or the repository.
No script is executed, authentication attempted or campus mutation performed.

## Usage

```sh
# Private cache only; no network request.
buaa spoc surface

# Explicit cache-miss observation of robots policy and the two fixed pages.
buaa spoc surface --online

# Explicit conditional revalidation using ETag/Last-Modified when supplied.
buaa spoc surface --refresh

# Refresh only the entry declaration in one governed target request.
buaa spoc surface entry --refresh

# Offline metadata for this observed, source-declared script; bytes stay private.
printf '%s' '{"url":"https://spoc.buaa.edu.cn/spocnew/js/app.a7c0879c.js"}' |
  buaa spoc script
```

Output is one structured JSON object (`type: spoc_public_surface`). `buaa schema`
provides the machine-readable contract. `surface [root|entry]` selects one fixed
page; omitting the selector observes both. A raised request gap can exceed the
client's 30-second bounded wait between pages: select each page deliberately,
without retry loops or lowering the governor. Default mode is cache only; an
offline miss is unavailable, not an empty surface.

`script` accepts exactly JSON `{ "url": "..." }` on stdin and returns
`type: spoc_public_script`. `--online` admits a governed cache miss;
`--refresh` conditionally revalidates only the selected script. Entry discovery
stays cache-first on the same client; refresh `surface entry` separately to
discover changed declarations. A syntactically allowed but undeclared URL
returns unsupported before the selected fetch, even if old script bytes exist.
Script bytes are immutable at their URL: conflicting refresh bytes are refused,
not overwritten. The filename fingerprint is opaque, not a publisher checksum.

Network-enabled modes allow only:

- `https://spoc.buaa.edu.cn/robots.txt`
- `https://spoc.buaa.edu.cn/`
- `https://spoc.buaa.edu.cn/spocnew/`
- Same-host `/spocnew/js/<name>.<8 lowercase hex>.js` only, where `name` is
  1–64 ASCII letters/digits/underscores/hyphens and the active entry HTML
  actually declares the selected URL. No query, fragment, credentials, custom
  port, source map, arbitrary API or external OSS URL.

Script discovery resolves the first active HTML `base[href]` only at the
reviewed same-origin `/`, `/spocnew/` or `/spocnew/js/` base paths; unsupported
bases fail closed. Template/noscript/foreign-namespace scripts, unsupported
types and classic `nomodule` fallback scripts are excluded. Script-type admission
reuses the original PDF viewer's reviewed classic MIME aliases and exact HTML
ASCII whitespace/explicit-type precedence. Unicode whitespace cannot activate a
data block or normalize an unreviewed source URL; literal admitted `src` values
remain distinct from resolved URLs. No inline source or import graph is
interpreted. HTML is bounded at 2 MiB, external script elements
at 32 and relevant ancestry at 128; selected scripts require HTTP 200, a
JavaScript MIME (`application/javascript` or `text/javascript`) and 1 byte to
8 MiB of content. Missing/wrong MIME is refused before cache commit. Syntax, publisher
signature and external checksum validation are not claimed.

The shared cross-process governor spans request, bounded body read, parsing and
atomic cache persistence. TLS verification is enabled; redirects, proxies,
cookies, decompression and automatic retries are disabled. The SPOC root is a
JavaScript redirect stub, so the client's no-redirect policy is what made the
canonical trailing-slash entry path (`/spocnew/`) observable. An explicit
disallow or unavailable robots policy fails closed.

## Current governed public-source observation (2026-10-02)

Bounded issue [#87](https://github.com/cyjin-yl/buaa-cli/issues/87) is a public
source prerequisite only. Every deliberate request used the existing account
governor with the retained 60,000/900,000-ms request/background policy, no pending
outcome or rejection latch and disarmed authentication. No alternate account
key, automatic retry, cookie forwarding, redirect, foreign request or TLS bypass.

| source | HTTP | bytes | SHA-256 | fetched_at_unix_ms |
|---|---|---|---|---|
| `/robots.txt` | 404 | 431 | `270d2fb55aa801662897590a27ec1c152407fa36be1d6678c27fd8c1859239e4` | `1790949702886` |
| `/spocnew/` | 200 | 2173 | `f728b87eb8579c7e1fa6ce689cbc1b85d30b2cbdda68a07add42bae00c081ba9` | `1790950297351` |
| `/spocnew/js/app.a7c0879c.js` | 200 | 2424757 | `5df4a46bb0277e60094ed1f2536a52e28a422558cb525fc28b1945ef8d7fa038` | `1790950469253` |

The first `script --online` refreshed stale robots and exited 8 before the
selected request because the retained gap exceeded the bounded wait. After the
full deadline, the old entry's `app.24020f98.js` request returned unsupported
HTTP status (exit 7; exact status is not exposed); no script bytes were cached.
There was no identical retry. Explicit `surface entry --refresh` then returned
one page with a changed hash and declarations for `app.a7c0879c.js` and
`chunk-vendors.12bfd5f9.js`. The old URL now fails source binding offline with
exit 3 and unchanged governor bytes. The newly declared app was selected in a
separate deliberate observation after the full shared deadline; its JavaScript
MIME and byte bounds passed. The vendor script was not fetched.

Independent private-cache base64 decode/length/SHA-256 verification matched the
Rust receipt and immutable flag. Actual `script` offline reuse returned the same
source/script hashes, size and original timestamp with `cache_status=hit`, no
governor mutation and no raw content in output. Focused offline proof passed nine
library cases plus one CLI case: source binding and selected-only refresh,
inert/first-base semantics, unreviewed/canonical URLs, resource bounds, missing or
wrong MIME, cache-poisoning refusal and payload-redacted errors. No full
JSON-Schema validator was available for the smoke run; schema output was read as
JSON, not claimed independently validated.

A separate retained regression reproduced Unicode `trim()` falsely admitting
inert script types/URLs and losing literal declaration whitespace, then passed
after sharing the existing HTML-only type rules and preserving literal `src`.
It also defends explicit empty-type precedence over legacy language attributes.
The college PDF viewer now uses that same admission helper with unchanged
classic/module policy, rather than a second convention.

Final locked offline build/full-tests/strict-all-target-clippy/formatter gate
passed: **204 library + 18 CLI tests**, two ignored, five suites. Actual final
native `script --refresh` returned `cache_status=revalidated`, revalidation
HTTP 200 at `1790952887461`, preserving original bytes/hash/fetched timestamp;
entry discovery stayed a cache hit. This is not a 304 receipt. Actual root-only
and entry-only offline commands, help, schema and capabilities succeeded with
structured JSON; aggregate SPOC status remains blocked. Twelve changed public
source/evidence files had zero credential-format scan hits; no comprehensive
security scan is claimed.

## Governed observation (2026-09-28)

One in flight, shared raised 60-second interval, TLS on, no cookies/redirects:

| path | status | bytes | SHA-256 | title | server-rendered forms |
|---|---|---|---|---|---|
| `/robots.txt` | 200 | 998 | (private cache) | n/a | n/a |
| `/` | 200 | 377 | `373cd4cd521ae2c33d27ce647d416b6a4d44523e100fa8503fd7f984af355243` | none (JS stub) | none |
| `/spocnew/` | 200 | 2173 | `5b6709aa5aafd07227e9348c619a5b0e07bff36059fc0ea33e8c1e6c897cdf9f` | 智学北航 | none |

Middleware is INCO; the root sets a `newSpoc` session cookie.

## Contract-relevant findings (draft)

1. **Client-rendered login.** Neither public page contains a server-rendered
   `<form>`. The SPOC login and course UI are delivered by client-side
   JavaScript. Any authenticated contract must therefore discover endpoints
   from the client bundle (and any XHR/fetch calls it makes), not by scraping a
   form. This is the principal open item for the owner.
2. **Entry path.** The canonical entry is `/spocnew/` (trailing slash); the bare
   `/spocnew` path HTTP-redirects to it.
3. **Session cookie.** The server issues `newSpoc`; a future authenticated flow
   must treat it as a session token, handle it only via the governed client
   (which currently disables cookie forwarding), and never print it.
4. **No completion automation.** Consistent with the acceptance item, any
   future adapter must not fabricate attendance or course completion.

## Not covered

- Authenticated course listing, material/video/PPT/subtitle endpoints and
  download rights.
- Any byte-verified download or provenance chain for course content.
- The `live` (classroom replay) acceptance item, which is separate.

Until the owner reviews this contract and provides a rights-cleared course
inventory, the SPOC acceptance item remains **blocked** and no authenticated
SPOC read is attempted.
