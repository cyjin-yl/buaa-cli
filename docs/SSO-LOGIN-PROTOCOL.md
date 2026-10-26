# BUAA classroom SSO observation record

## Scope and authorization

This is a sanitized development research record dated 2026-10-26, not a
working-service acceptance certificate or permission to evade service controls.
The account owner authorized observation of their normal login. Challenges must
be completed normally by the operator; no fabricated interaction telemetry,
challenge bypass, weakened TLS or automatic authentication retry is justified.
Camoufox was a development observation tool, not a CLI runtime dependency.

Only protocol structure is published here. Passwords, account identifiers,
service tickets, session cookies, execution tokens, private course identifiers
and original account-page captures must not be committed or published. Public
script inspection does not grant a redistribution license for that script.

## Observed relying-party flow

The retained operator-driven browser trace began at the classroom root. Its
structural request and response sequence was:

| Stage | Observed request | Observed response |
| --- | --- | --- |
| Application entry | `GET classroom.msa.buaa.edu.cn/` | HTTP 200 application shell |
| Initial SSO handoff | `GET yjapi.msa.buaa.edu.cn/casapi/index.php` with `auType`, `forward`, `r`, `tenant_code` | HTTP 302 |
| Handoff continuation | Same callback route without `auType` | HTTP 302 to the SSO login route |
| Login document | `GET sso.buaa.edu.cn/login` with `service` | HTTP 200 HTML |
| Visible login document | `GET sso.buaa.edu.cn/cas/login-normal.html` | HTTP 200 HTML |
| Telemetry observation | `POST sso.buaa.edu.cn/fingerprint` | No response recorded in that trace |
| Credential submission | `POST sso.buaa.edu.cn/login` | HTTP 302 to the callback with `ticket` |
| Ticket-bearing callback | `GET yjapi.msa.buaa.edu.cn/casapi/index.php` with `ticket` | HTTP 302 to the same route without `ticket` |
| Ticketless continuation | Same callback route without `ticket` | HTTP 302 to the classroom root |
| Application landing | `GET classroom.msa.buaa.edu.cn/` | HTTP 200 |

These are event order and status observations. The recorder did not retain
per-request timestamps or completion events, and deduplicated request URLs.
It therefore cannot prove millisecond timing, complete request multiplicity,
all network traffic or full response-body completion. A missing response event
is not proof of an abort, timeout or server acceptance.

In the recorded platform-generated handoff, the nested `forward` target was the
classroom root, not a signed course URL. This agrees structurally with the
pinned CLI service. Earlier historical SPOC-signed course forwards are another
entry path, not evidence that every classroom login requires such a signature.
`auType` appeared on initial entry, not on the recorded ticket redemption.
Do not generalize this deployment's exact callback sequence to all CAS systems.

## Parent form and visible controls

A separately retrieved SSO page with the reviewed service contained a parent
form with `method="post"`, `id="loginForm"`, `action="login"`. The visible
`cas/login-normal.html` document contained the username/password controls and
called `parent.doLogin(...)`; it had no native form of its own. The parent
function assigned the credentials and login type to its form, then activated
its submit control.

The safe projection of one successful development-browser capture retained
this field order, without any captured values:

```text
username, password, submit, type, execution, _eventId
```

The fixed protocol fields matched `submit=LOGIN`, `type=username_password`
and `_eventId=submit`. The execution token was per-page and must not be reused
or archived as a public fixture. These fields are deployment observations,
not requirements of the CAS protocol in general.

For development interaction, selecting the first password input was wrong:
the parent document and hidden login variants also contained controls.
Selecting the visible `cas/login-normal.html` frame and its intended visible
controls resolved that observation-script error. The successful reproduction
used native pointer/keyboard operations rather than `fill()` or value
assignment. This does not establish that every programmatic value assignment
fails, nor authorize impersonating a human to defeat a service restriction.

## Guard script observations

The separately retrieved public `guard.core.js` source:

- starts browser fingerprint collection through `BotDetector.getFingerprint`;
- compacts pointer, keyboard and input interaction records;
- wraps `loginPasswordInternal` with a pre-submission `POST /fingerprint`;
- includes identity, page, elapsed-time and fingerprint/interaction information;
- uses a short client-side timeout and invokes the original login function
  after the upload promise settles, including its failure path.

This describes client-side code only. It does not establish the server's
anti-bot policy, whether telemetry is mandatory, whether it is stored, or
whether its absence caused a CLI failure. The script's input bucketing does
not establish that its complete payload is free of sensitive data. Do not
replay or fabricate the payload, spoof fingerprints, or disable challenges.

## Failed CLI observations and unresolved cause

Retained sanitized CLI receipts reported SSO GET 200, credential POST 302 and
callback HTTP 500. The inspected callback query-name projections included
`ticket`; they do not preserve ticket bytes, complete request equivalence or
the original error body. The CLI's source inserted the configured request gap
between HTTP hops. The original runtime retained a 60-second request policy.

Ticket expiration is a plausible timing hypothesis, not an established cause.
Upstream Apereo CAS documentation lists a default service-ticket lifetime of
10 seconds and permits per-service overrides. BUAA's deployed CAS version and
actual policy were not observed. A service error can also arise from relying-
party processing, ticket/service mismatch or another server failure. Neither
HTTP 500 nor a redirect proves password correctness or rejection.

Missing discriminating evidence includes the completed callback's non-secret
error reason, actual request timing, and a controlled comparison that changes
only the suspected factor. Do not obtain it by replaying a consumed ticket or
by bypassing required request policy. If timing policy and the service lifetime
conflict, report the incompatibility; do not silently exempt redirects.

## Acceptance and retention limits

The safe development capture reports HTTP 200 and application code 200 for
`userapi/v1/infosimple`, but its identity-marker check was false and no selected-
lesson probe was verified. The operator reported successful browser login;
this is not proof of the CLI's `session_observed` contract, complete service
access, media rights, live playback or subtitle/media association.

A prior diagnostic incorrectly persisted and printed an encoded credential
because it replaced only the plaintext password. The affected owned raw
capture and credential scratch file were removed; a structural receipt was
retained. That cleanup does not erase historical output. Future observers
must never persist raw authentication bodies or capture a credential page
and attempt to redact it afterward.

## References

- [CAS protocol specification](https://apereo.github.io/cas/7.3.x/protocol/CAS-Protocol-Specification.html)
- [Apereo service-ticket expiration policy](https://apereo.github.io/cas/7.3.x/ticketing/Configuring-Ticket-Expiration-Policy-ST.html)
- [General implementation notes](CAS-LOGIN-PROTOCOL.md)
