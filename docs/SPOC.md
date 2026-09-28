# SPOC public surface — contract draft

**Status: PENDING OWNER REVIEW.** This is contract *evidence and a draft*, not an
approved service contract. It authorizes no authenticated read, no course
inventory, and no download. The SPOC acceptance item stays **blocked** until an
owner reviews this contract and supplies a rights-cleared course inventory.

`buaa spoc surface` is read-only contract tooling. It is not an authenticated
adapter: it fetches the two fixed public SPOC paths through the shared process
governor (robots policy checked first) and reports only sanitized structural
facts — HTTP status, content type, byte length, SHA-256, document title and
form shape. Response bodies, input names and values never enter the output,
logs or the repository. No authentication is attempted and no mutation is
possible.

## Usage

```sh
# Private cache only; no network request.
buaa spoc surface

# Explicit cache-miss observation of robots policy and the two fixed pages.
buaa spoc surface --online

# Explicit conditional revalidation using ETag/Last-Modified when supplied.
buaa spoc surface --refresh
```

Output is one structured JSON object (`type: spoc_public_surface`). `buaa schema`
provides the machine-readable contract. Default mode is cache only; an offline
miss is unavailable, not an empty surface.

Network-enabled modes allow only:

- `https://spoc.buaa.edu.cn/robots.txt`
- `https://spoc.buaa.edu.cn/`
- `https://spoc.buaa.edu.cn/spocnew/`

The shared cross-process governor spans request, bounded body read, parsing and
atomic cache persistence. TLS verification is enabled; redirects, proxies,
cookies, decompression and automatic retries are disabled. The SPOC root is a
JavaScript redirect stub, so the client's no-redirect policy is what made the
canonical trailing-slash entry path (`/spocnew/`) observable. An explicit
disallow or unavailable robots policy fails closed.

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
