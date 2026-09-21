# Governed campus gateway client

BUAA CLI contains a real fixed-endpoint SRun client for usage, login and logout. Development proof is entirely offline with synthetic loopback responses. **No real campus gateway request, authentication attempt or logout has been authorized or performed**, so live compatibility remains unverified.

The adapter deliberately excludes behaviors observed in references: HTTP AC discovery, network-interface/DNS probing, credential files, password arguments, raw response errors, invalid-certificate modes, multi-dial, automatic retry, automatic login refresh and continuing past a security-risk/challenge notice.

## Usage

```sh
# Private cache only; no request.
buaa gateway usage

# Explicitly allow one governed usage read on cache miss.
buaa gateway usage --online

# Explicitly re-read usage instead of accepting the cache.
buaa gateway usage --refresh
```

Usage output omits username, real name and MAC fields. It exposes nullable traffic byte counters, online IP, duration and balance facts plus fetch time/body hash/cache provenance. The cache is private under the effective user's passwd home and is validated before use. Normal interactive reads use the five-second global request interval. Any future scheduler/background worker must additionally use `BackgroundPoll` and the global fifteen-minute minimum; this CLI does not install a poller.

## One deliberate authentication attempt

Credentials are bounded JSON on stdin—never argv, repository files, diagnostic URLs or logs. The operator must first arm exactly one authentication attempt:

```sh
printf '%s\n' '{"intent":"RESUME GATEWAY AUTH"}' | buaa gateway resume-auth
```

This makes no network request, does not clear cooldowns or unknown outcomes, and does not bypass a challenge. Then invoke exactly one login flow:

```sh
printf '%s\n' '{
  "username":"<stdin-only>",
  "password":"<stdin-only>",
  "ip":"10.0.0.2",
  "ac_id":62,
  "intent":"LOGIN <stdin-only> 10.0.0.2"
}' | buaa gateway login --online
```

The literal example values are placeholders, not a working account or discovered campus configuration. `ip` and `ac_id` must be deliberately supplied; the CLI does not send an insecure HTTP discovery request or inspect local interfaces automatically.

Challenge acquisition is one governed interactive request. Credential submission is a second request after the global completion gap and uses `RequestKind::Authentication`, consuming the one-shot permission. There is no retry/fallback loop. A final send failure, indeterminate 2xx body, credential rejection, 401/403, reliable challenge or lock signal leaves authentication latched until another deliberate `resume-auth`. The CLI zeroizes the original login stdin buffer when the command returns, and the parsed password field zeroizes on every drop path; challenge-bound derived fields live only for the bounded request and are never stored or returned.

The SRun-compatible material is produced by original Rust code: XXTEA-style `info`, custom base64 alphabet, HMAC-MD5 password and SHA-1 checksum. A synthetic vector from an independent implementation pins compatibility; no upstream implementation was copied.

## Logout plan and commit

Create an immutable preview without network access:

```sh
printf '%s\n' '{"username":"<stdin-only>","ip":"10.0.0.2","ac_id":62}' \
  | buaa gateway logout-plan
```

The reply omits the raw username, reports its domain-separated SHA-256, binds username/IP/AC ID into `plan_hash`, and gives the exact required intent. Commit by supplying the original fields, returned hash and intent:

```sh
printf '%s\n' '{"username":"<stdin-only>","ip":"10.0.0.2","ac_id":62,"plan_hash":"<returned>","intent":"COMMIT GATEWAY LOGOUT <returned>"}' \
  | buaa gateway logout-commit --online
```

Commit validation occurs before cache/governor/network access. A successful commit writes a private receipt while holding the request lease; repeating the identical plan returns `idempotent_hit` without another request. Logout never accepts a password or retries. This development work does not authorize a real commit.

## Transport and evidence

Production egress is fixed to TLS-validated `https://gw.buaa.edu.cn` and exactly:

- `/cgi-bin/rad_user_info`
- `/cgi-bin/get_challenge`
- `/cgi-bin/srun_portal`

Redirects, proxies, cookies, referrers, response decompression, connection reuse and reqwest retries are disabled. Bodies are bounded to 512 KiB. JSONP callback and JSON structure must match; errors are static and never echo bodies, query URLs, user identifiers or credential-derived values. The shared governor lease spans request, bounded response parsing, application classification and usage-cache persistence.

Synthetic real-loopback tests verify:

- original crypto against an independent vector;
- usage normalization/cache reuse while redacting identity fields;
- explicit resume before any challenge request;
- separately governed challenge and credential submission, plus logout plan/commit with one governed commit and idempotent receipt reuse;
- no plaintext password or Cookie in HTTP requests;
- successful authentication consumes the one-shot token;
- credential rejection consumes the token and latches account safety;
- malformed typed intents fail before transport construction.

These tests establish implementation behavior, not current campus endpoint readiness, `ac_id` correctness, owner account permission or a successful live session. The aggregate gateway acceptance remains partial because bounded live usage/login/logout observations are still missing. No development prompt alone authorizes those observations.
