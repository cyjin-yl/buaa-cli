# Graceful Degradation and Self-Reporting

## Principle

Every `buaa-cli` command MUST fail gracefully. A parser mismatch, schema drift, or missing selector is not a hard failure when the underlying source bytes were successfully retrieved. The command returns a degraded-success payload containing:

- `raw_html`: base64-encoded original response bytes (for HTML surfaces).
- `content_type` and `body_byte_length`: response metadata.
- `fallback_reason`: machine-readable explanation of which structured assumption failed.
- `retrieval`: existing governed retrieval facts (URL, SHA-256, cache status, timestamps).

Fallback output is not an error exit; exit code remains 0 when any verifiable source bytes are present. This lets Agents inspect, diff, and re-parse originals without issuing another network request.

## When fallback activates

- HTML parser selectors no longer match the observed DOM.
- Content-Type is HTML but the expected listing/article structure is absent.
- Date/title/category extraction yields zero rows where the source previously provided them.
- A new preview/attachment markup variant appears that the bounded extractor cannot safely interpret.

## When fallback does NOT activate

- HTTP 4xx/5xx from the source (those remain governed error paths).
- Authentication or challenge screens (governor safety latch handles them).
- Non-HTML content types (e.g., PDF, images) that have their own bounded paths.
- Cache miss with `--offline` (no bytes to fall back to).

## `buaa-cli report`

Purpose: let Agents and users create GitHub Issues automatically when they encounter fallback states or unexpected behavior.

Behavior:

1. Check `gh auth status -h github.com`.
2. If authenticated, spawn `gh issue create --repo cyjin-yl/buaa-cli --title ... --body ... --label ...`.
3. Return the created Issue URL.
4. If `gh` is missing or not authenticated, return a `blocked` result with exact installation/login steps; never fabricate an Issue URL.

Required input fields:

- `title` (string): concise problem summary.
- `body` (string): reproduction command, observed output, environment facts, affected acceptance IDs.
- `labels` (array of strings, optional): e.g., `["fallback", "agent-report"]`.

## Agent integration

When an Agent observes a `fallback_reason` in command output, it SHOULD:

1. Preserve the raw response bytes locally (they are already in the payload).
2. Invoke `buaa-cli report` with the reproduction command and `fallback_reason`.
3. Continue with the raw bytes for any downstream task instead of retrying the network request immediately.

## Scope

This contract applies to all current and future commands that parse external HTML or JSON sources: `announcements`, `archive`, `organizations`, `spoc`, and any upcoming college adapters.
