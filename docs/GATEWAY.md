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

Each invocation represents a new logout operation and generates a fresh `operation_id`. The reply omits the raw username, reports its domain-separated SHA-256, and binds the username/IP/AC ID plus operation ID into `plan_hash`. Commit must include the exact operation ID, returned hash and required intent:

```sh
printf '%s\n' '{"username":"<stdin-only>","ip":"10.0.0.2","ac_id":62,"operation_id":"<returned>","plan_hash":"<returned>","intent":"COMMIT GATEWAY LOGOUT <returned>"}' \
  | buaa gateway logout-commit --online
```

Validation occurs before cache/governor/network access. A per-account process-shared operation lock serializes receipt checks, the mutation boundary and persistence; the shared governor still controls the actual request. Repeating one completed plan returns its private receipt as `idempotent_hit` without another request. A fresh plan has a distinct operation ID and can represent a later logout intent.

After the final shared-governor lease is acquired and before sending, the client durably records an account-level unknown-outcome barrier. It is cleared only after a confirmed success response and a persisted receipt. Any later transport, response-classification, receipt or journal failure leaves the barrier and returns `unknown_outcome`; while it exists, all logout commits for that account fail closed. Do not retry that operation.

### Recovering an unknown outcome

Inspect the local barrier without network access:

```sh
printf '%s\n' '{"username":"<stdin-only>","ip":"10.0.0.2","ac_id":62}' \
  | buaa gateway logout-recovery-plan
```

`no_unknown_outcome` means no barrier needs review. `review_required` returns the operation ID, plan hash, recovery hash and exact typed intent while explicitly reporting `remote_state: unknown` and `network_request_performed: false`. Supply the same username, IP and AC ID as the original logout plan; the recovery preview verifies those fields against its bound operation before it can be committed.

```sh
printf '%s\n' '{"username":"<stdin-only>","ip":"10.0.0.2","ac_id":62,"operation_id":"<returned-operation-id>","plan_hash":"<returned-plan-hash>","recovery_hash":"<returned-recovery-hash>","intent":"RESOLVE UNKNOWN GATEWAY LOGOUT <returned-recovery-hash>"}' \
  | buaa gateway logout-recovery-commit --offline
```

This local-only operation records that the operator reviewed the uncertainty; it performs no remote read/retry and never claims the portal is disconnected. A durable resolved tombstone prevents replaying the same operation. A later, deliberately created plan has a different operation ID. This development work does not authorize a real commit, authentication or live observation.

## Transport and evidence

Production egress is fixed to TLS-validated `https://gw.buaa.edu.cn` and exactly:

- `/cgi-bin/rad_user_info`
- `/cgi-bin/get_challenge`
- `/cgi-bin/srun_portal`

Redirects, proxies, cookies, referrers, response decompression, connection reuse and reqwest retries are disabled. Bodies are bounded to 512 KiB. JSONP callback and JSON structure must match; errors are static and never echo bodies, query URLs, user identifiers or credential-derived values. The shared governor lease spans each request, bounded response parsing, application classification and private cache/receipt persistence.

Synthetic real-loopback tests verify:

- original crypto against an independent vector;
- usage normalization/cache reuse while redacting identity fields;
- explicit resume before any challenge request;
- separately governed challenge/login and logout; one identical operation has one governed commit and receipt reuse, while a fresh plan can commit again;
- malformed 2xx responses and receipt-persistence failures retain the account-wide unknown barrier; a cross-process same-plan regression sends exactly once;
- a failed pre-send journal preflight emits no request and releases the reservation without leaving an unfinished governor lease;
- offline review keeps remote state explicitly unknown, performs no request and prevents replaying the resolved operation;
- no plaintext password or Cookie in HTTP requests;
- successful authentication consumes the one-shot token;
- credential rejection consumes the token and latches account safety;
- malformed typed intents fail before transport construction.

These tests establish implementation behavior, not current campus endpoint readiness, `ac_id` correctness, owner account permission or a successful live session. The aggregate gateway acceptance remains partial because bounded live usage/login/logout observations are still missing. No development prompt alone authorizes those observations.
