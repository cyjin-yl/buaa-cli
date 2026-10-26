# CAS client development and diagnosis

## Protocol facts versus deployment facts

A common CAS web login begins when a relying party directs the browser to a
CAS login endpoint with an approved `service` URL. Following successful
authentication, CAS can redirect the browser to that service with a single-use
service ticket. The relying party validates the ticket and establishes its
own application session. Existing SSO sessions, renew/gateway modes, MFA,
federated authentication and non-browser APIs can produce different flows.
A `service` parameter is therefore not a universal prerequisite for every
visit to a CAS login page.

Use the relying party's reviewed service declaration. Registration and service
matching are deployment policy; a client must not invent or widen the
credential target. An unauthorized-service page is not a credential verdict.

## Redirects and ticket lifetime

Follow the observed, allowlisted redirect chain with bounded hop counts and
correct method/body semantics. A deployment may redirect a ticket-bearing
callback to a ticketless callback before reaching the application. Others do
not. Do not hard-code that extra request or stop at an arbitrary first 302.

Tickets are normally single-use and time-bounded. Apereo CAS's documented
default service-ticket lifetime is 10 seconds, with service-specific override
support. That is not proof of another server's version or configuration.
Request delays can be relevant, but a slow request followed by HTTP 500 does
not establish ticket expiration. Preserve required request limits; if a
service contract is incompatible, report it rather than silently treating a
redirect chain as exempt.

Never replay a ticket to recover a missing error body. A redirect alone is
not account verification or application acceptance.

## Source-owned form handling

The actual credential controls, per-page tokens, submitter and effective form
action come from the reviewed source and active browser behavior. Names such
as `execution`, `_eventId`, `type` and `submit` are deployment/framework details,
not a universal CAS field schema. A visible framed document may call a parent
function that populates a separate native form. Inspect both document roles
without promoting a hidden control to the visible user interaction target.

Preserve the selected form's successful-control semantics and encoding. Do not
copy request tokens from another page, guess field values, or assume one
server's six-field body applies to another server. Keep the CLI independent
of a development browser unless browser automation is an explicit product
requirement; the current project uses the browser only for development.

## Normal-browser observation

For an authorized development observation:

1. Reuse a verified installed browser in a fresh context, without reading an
   existing user's profile or exporting unrelated authentication state.
2. Establish the required request admission and privacy boundaries before
   navigation. A passive listener alone does not enforce request limits.
3. Use the intended visible controls. When the task requires pointer/keyboard
   interaction, do not use `fill()`, direct value assignment or forced clicks
   into hidden controls. Do not fabricate interaction data or modify the
   page's checks to make verification pass.
4. Let the operator complete any presented challenge normally. Do not automate
   challenge solving, bypass restrictions or assume a fingerprint upload is
   optional merely because client code tolerates a timeout.
5. Record fixed action labels, bounded route labels, opaque local request IDs,
   method/status/MIME labels and real monotonic timestamps when available.
   Do not record individual keys, field values, arbitrary locators, complete
   URLs, raw headers, HAR, traces or authentication-body dumps.
6. Label omissions honestly: observers can miss cache paths, workers,
   cancellations, duplicate requests or response completion. Event sequence
   alone is not a timing measurement or full-coverage proof.
7. Use only an inert, approved redacted projection for published visual proof.
   Never capture a live credential page and redact it afterward.

HTTP form encoding transforms secrets. Replacing only the literal password
in an encoded request body is not redaction. The safe default is not to
persist the body at all; keep any unavoidable inspection inside a trusted
nonrecording boundary and export only reviewed non-secret facts.

## Failure classification and acceptance

| Evidence | What it establishes |
| --- | --- |
| Explicit unauthorized-service response | A service-policy or service-shape refusal; not a password verdict |
| Explicit reviewed credential error | A credential refusal for that observation, not permission to retry automatically |
| Error status at a callback | A failed callback; expiration, replay, service mismatch and server faults remain candidates |
| Visible active challenge | Required normal operator interaction; not permission to bypass it |
| Redirect or cookie presence | An intermediate authentication artifact; not positive application confirmation |
| Expected application response validated against the authorized selection | Only that declared application scope, not universal account or media rights |

A robust client preserves status, Retry-After and challenge facts through
bounded body processing and reports an unknown cause when its evidence is
insufficient. It does not relabel an unclassified HTTP 500 as a proven ticket
rejection or wrong password.

## References

- [CAS protocol specification](https://apereo.github.io/cas/7.3.x/protocol/CAS-Protocol-Specification.html)
- [Service-ticket expiration and per-service overrides](https://apereo.github.io/cas/7.3.x/ticketing/Configuring-Ticket-Expiration-Policy-ST.html)
- [Bounded BUAA deployment observation](SSO-LOGIN-PROTOCOL.md)
