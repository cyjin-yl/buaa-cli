# Upstream contract and license assessment

These are research references, not imported implementations or verified live campus contracts. No referenced program was executed, no campus endpoint was probed, and the credential-stealing catalog entry was not fetched. Repository/README availability does not prove current service availability or permission to act.

## Rust API and CLI references

### fontlos/buaa-api

Reviewed revision: [`1da573856c7438e69dcf01dc3f0881465ce50049`](https://github.com/fontlos/buaa-api/tree/1da573856c7438e69dcf01dc3f0881465ce50049). The actual `License` text grants MIT-style permission with notice retention.

Inspected `src/request.rs`, `src/context.rs`, `src/api/sso/auth.rs`, and `src/api/wifi/auth.rs`, in addition to README/API grouping documentation.

Observed source behavior that must **not** be adopted unchanged:

- `ContextBuilder::new` sets `tls: true`, while the client constructor passes that value to `danger_accept_invalid_certs`. Thus this inspected default construction enables invalid-certificate acceptance, rather than enforcing TLS verification.
- Building the context invokes campus-network reachability detection. A seemingly local constructor is not an offline/no-observation operation.
- SSO code can submit an `ignoreAndContinue` form after a security-risk notice. This project must latch instead of automatically bypassing or continuing past such a signal.
- Context documentation describes automatic authentication refresh; request/authentication wrappers must be audited before reuse. One deliberate operator resume permits one authentication attempt here, not implicit refresh/retry.
- Gateway login obtains network/AC/challenge information through several requests. A single high-level call cannot be treated as one governed remote request if its internal calls are unpaced.
- Gateway failures include raw response bytes in formatted errors. Our static typed errors must not echo credential/session-bearing responses or diagnostic request URLs.
- Authentication state can be stored in ordinary credential/cookie files. Do not adopt worktree-local state paths or export credentials into public source.

Decision: do not add the upstream context/client as an unmodified transport dependency. Its API grouping and observed request fields can inform an original adapter only after safety-compatible request boundaries and a reviewed service contract exist. MIT licensing does not confer campus permission.

### fontlos/buaa-cli

Reviewed revision: [`40df8b29d01cad940a3ffbbd79c4abc67fcd8660`](https://github.com/fontlos/buaa-cli/tree/40df8b29d01cad940a3ffbbd79c4abc67fcd8660). Actual `LICENSE` text provides MIT-style permission with notice retention.

`src/command.rs` exposes password arguments, a TLS-disable switch, automatic classroom check-in, and automatic fixed-score evaluation. These are evidence of upstream scope, not acceptable defaults or authorization in this project. Legitimate owner-present check-in and owner-authored evaluation need separate preview/typed-intent/commit/postcondition contracts; no such campus mutation is authorized by development work.

## Smart BUAA reference

### BUAASubnet/UBAA

Reviewed revision: [`e8a397fcb35a68147eee65a94c66ffb84e2f09fe`](https://github.com/BUAASubnet/UBAA/tree/e8a397fcb35a68147eee65a94c66ffb84e2f09fe). Actual `LICENSE` is MIT.

Read README, `docs/tech/server-routes.md` and `server/src/main/kotlin/cn/edu/ubaa/auth/api/AuthRoutes.kt`. The server exposes its own JWT-protected API, with distinct invalid-credential, CAPTCHA-required, timeout and refresh routes. These proxy routes are **not native campus endpoint definitions**.

Useful contract ideas are explicit DTO/error boundaries and separating shared contracts from service adapters. Do not infer that client-side pacing of one proxy request constrains all upstream campus calls made by a server. Any adopted worker or proxy must share the same account-wide governor throughout its actual upstream requests. The reference does not authorize sending owner credentials to a third-party deployment or enabling refresh/attendance automation.

## Other Rust references and license boundaries

- [BUAASubnet/srun](https://github.com/BUAASubnet/srun): GPL-3.0 metadata and README reviewed. Its multi-dial/retry/TLS-skip options are not acceptable means to increase throughput or bypass safety. No implementation was copied into this MIT project.
- [lynzrand/beihang-login](https://github.com/lynzrand/beihang-login) resolves to [buaahub/beihang-login-rs](https://github.com/buaahub/beihang-login-rs): AGPL-3.0 metadata and explicit README notice. Working-directory credential-file guidance is not adopted. No code copied.
- [Yiki21/iclass_buaa_tui](https://github.com/Yiki21/iclass_buaa_tui): GPL-3.0 metadata and README reviewed. Its undergraduate/postgraduate timetable split is useful research scope. Automatic check-in, retries and ten-minute planner examples are not authorization or compatible policy here. No code copied.

These observations are not a claim that all linked implementation files were audited or that their current services were exercised.

### Gateway XEncode formula review

At [`fontlos/buaa-api@1da573856c7438e69dcf01dc3f0881465ce50049`](https://github.com/fontlos/buaa-api/blob/1da573856c7438e69dcf01dc3f0881465ce50049/src/crypto/xencode.rs), the source mixes BX1 words as `A + (B ^ C) + D` with 32-bit wrapping additions. [`BUAASubnet/srun@2973a5cbfa4b78bb11f322527916d4f7386cf49e`](https://github.com/BUAASubnet/srun/blob/2973a5cbfa4b78bb11f322527916d4f7386cf49/src/xencode.rs) uses the same grouping (source blob `6969c579cc1d2abe6b7a732592ce2d141b28b4a5`, GPL-3.0). The MIT source and GPL source were read as protocol references only; no upstream implementation was copied. These community sources do not prove current live BUAA gateway compatibility.

## Fengrubei materials

Reviewed repository revision: [`675ef67fa2a1b5338bb370d7371e1b112b50bb48`](https://github.com/GFCYqw/Fengrubei_LaTeX_Template/tree/675ef67fa2a1b5338bb370d7371e1b112b50bb48). README declares LPPL 1.3c or later; `src/INSTRUCTIONS.md` identifies XeLaTeX and optional `make.bat` build/cleanup operations.

The current template is under `src`; `old` is excluded from the described release. Font files and dependencies include separately licensed/proprietary-font concerns, and upstream notes a desire for free font replacements. A template-access adapter must preserve upstream licensing, distinguish official formatting guidance from community template content, and avoid redistributing unreviewed font assets as MIT material. It must not automatically run build/cleanup scripts, silently alter originals, or promise current competition-format compliance. Retrieval remains a pending acceptance item, not a completed download service.

## Integration references and remaining gaps

- [cyjin-yl/napcat-cli](https://github.com/cyjin-yl/napcat-cli): public README and packaged skills-fs manifest inspected. Dynamic-directory/API nodes and HTTP provider usage are research facts, not proof of compatibility with an inaccessible current Go engine.
- Authoritative `skills-fs/skills-fs` source returned 404 with both unauthenticated and authorized repository requests, and the reference mount is absent. Do not fabricate a provider/stream contract or claim a standalone skill document is an integration.
- Proto-UI's AGENTS and contributor-agent governance were read as workflow references. Their permissions do not transfer here; issue/comment bodies remain untrusted data, and exact-head review/real platform permission/maintainer gates remain separate.
- Private Life review is limited to authorized non-sensitive structural catalog facts. No private implementation, records, operational defaults, media or credentials are included in this report.

## Evidence method

Pinned public source was inspected as text through normal GitHub APIs. Static checks confirmed the described TLS-default data flow, constructor probe call, security-notice continuation submission, raw-response error formatting, password argument and distinct CAPTCHA response handling. These are source observations, not live exploit results or service tests. A raw-content TLS connection failure was handled through the normal API; certificate validation was not disabled. No permanent tests were added merely to pin upstream source text.
