# Authoritative organization directory

`buaa organizations list` reads one fixed official source: the BUAA main website's `教学科研机构` directory. It does not crawl college sites, infer organizations from DNS, or combine an unofficial list.

## Usage

```sh
# Private cache only; no network request.
buaa organizations list

# Explicit cache-miss observation of robots policy and the fixed directory.
buaa organizations list --online

# Explicit conditional revalidation using ETag/Last-Modified when supplied.
buaa organizations list --refresh
```

Output is one structured JSON object. `buaa schema` provides the machine-readable contract. Default mode is cache only; an offline miss is unavailable, not an empty directory.

Network-enabled modes allow only:

- `https://www.buaa.edu.cn/robots.txt`
- `https://www.buaa.edu.cn/jgsz/jxkyjg02.htm`

The shared cross-process governor spans request, bounded body read, parsing and atomic cache persistence. TLS verification is enabled; redirects, proxies, cookies, decompression and automatic retries are disabled. Robots 404/410 means no policy was supplied; an explicit disallow or unavailable policy fails closed. Authentication rejection, reliable challenge signals and 429 cooldowns retain the same latch/backoff semantics as other governed sources. No account login or campus write is performed.

## Directory semantics

Each result preserves:

- source order and official category;
- source label text;
- the literal `href` attribute when present;
- a normalized HTTP(S) URL only when it can be represented safely;
- link kind: `http`, `https`, `missing`, `non_http`, or `invalid`;
- whether the source anchor is hidden by its class/inline style.

No missing URL is reconstructed. A `javascript:void(0)` link remains non-HTTP. Plain HTTP links are not silently upgraded to HTTPS. Hidden entries still present in the official HTML are returned and marked. A combined source label remains one directory entry rather than being split into institutions the source did not separately link.

The parser requires the official directory structure, bounds the HTML to 2 MiB, accepts UTF-8 only, and rejects duplicate categories, empty/control-bearing labels or more than 64 categories/512 entries. A site redesign fails as unavailable instead of returning plausible partial data.

Completeness means every anchor inside every recognized organization box in the captured official directory document. It does **not** claim that the document names every university unit, that every linked site is reachable/current, or that hidden/unlinked institutes have no other official page.

## Governed observation evidence

On 2026-09-20 the owner authorized at most three read-only requests to the official site. The production shared governor enforced one in flight and at least five seconds after completion. No authentication, retry or mutation occurred:

1. `robots.txt`: HTTP 404; body SHA-256 `a71f7d336711705a8ac403fc504633df3f32cf29973fd72a6d6099a032818aed`.
2. Homepage: HTTP 200; body SHA-256 `b936471fe3aaad7ae6e4753b0183f347fd637aaa18c59ecf893c6703c3911ebd`; linked `jgsz/jxkyjg02.htm` as 教学科研机构.
3. Linked directory: HTTP 200; body SHA-256 `f491e3ae91fc9ffd37b04e3cc3a5e7b8744f4c90950b3fb1498b3f21a16b56d9`.

The Rust production parser processed the privately retained directory response offline as six categories and 50 entries: six marked hidden in source, five missing hrefs and one non-HTTP href. Raw HTML is not committed. A sanitized normalized evidence snapshot is [data/organizations-2026-09-20.json](data/organizations-2026-09-20.json).

Synthetic loopback tests exercise the actual reqwest path, robots 404 handling, unchanged five-second spacing, allowlisted routes, cache hit and no Cookie forwarding. Synthetic parser tests defend visible/hidden, missing, non-HTTP and relative link behavior. Announcement listing/full-text/attachment retrieval remains a separate acceptance item; this directory adapter does not imply it.
