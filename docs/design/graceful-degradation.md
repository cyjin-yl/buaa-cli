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

## `buaa report`

Purpose: let Agents and users create GitHub Issues automatically when they encounter fallback states or unexpected behavior.

Behavior:

1. Validate the complete request as a typed object before any `gh` call. The object has required string fields `title` and `body`, plus an optional `labels` array containing only strings; unknown or malformed fields are rejected and never discarded.
2. Check `gh auth status -h github.com`. If `gh` is missing, return `blocked` with installation and login steps. A failed status check means authentication could not be confirmed, not necessarily that the user is logged out; guide the operator to inspect status and connectivity, then use `gh auth login` if needed. Authentication stderr is not returned because it may contain secrets.
3. If authenticated, spawn `gh issue create --repo github.com/cyjin-yl/buaa-cli --title ... --body-file - --label ...` and write the body through stdin, never as a command-line argument. Bind the writer to the same GitHub host as the authentication check, regardless of `GH_HOST`.
4. Return `created` only when the writer emits the canonical `https://github.com/cyjin-yl/buaa-cli/issues/<positive-id>` URL. A successful or uncertain writer without that URL returns `unknown_outcome` with `reconciliation: required` and `automatic_retry: false`; it is not treated as a retryable authentication failure and no automatic retry is performed.

Required input fields:

- `title` (string): concise problem summary.
- `body` (string): reproduction command, observed output, environment facts, affected acceptance IDs.
- `labels` (array of strings, optional): e.g., `["fallback", "agent-report"]`.

Runtime verification of the synthetic report regressions is pending; no real Issue creation or authentication is implied by this contract.

`buaa schema` exposes the strict report input and the `created`, `blocked`, and `unknown_outcome` output states. Unexpected command-line arguments are rejected before stdin or `gh` is consumed. Input content must be sanitized by the reporting operator or Agent; the command does not automatically redact a private body.

## Agent integration

When an Agent observes a `fallback_reason` in command output, it SHOULD:

1. Preserve the raw response bytes locally (they are already in the payload).
2. Invoke `buaa report` with a sanitized reproduction command and `fallback_reason`; never attach raw private HTML/JSON, credentials, or session-bearing URLs to the public Issue.
3. Continue with the raw bytes for any downstream task instead of retrying the network request immediately.
4. After a sanitized Issue readback, the reporting Agent SHOULD launch a bounded repair subagent using authorized `gh` and the approved `gh stack` workflow, returning the exact branch/PR/head and verification evidence. The Agent MUST NOT self-approve or auto-merge.

## Scope

This contract applies to all current and future commands that parse external HTML or JSON sources: `announcements`, `archive`, `organizations`, `spoc`, and any upcoming college adapters.
