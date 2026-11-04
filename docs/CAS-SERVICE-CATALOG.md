# BUAA CAS relying-party catalog (observed 2026-11-04)

Ground truth gathered with an authorized owner-credential login. Every entry below
was **observed**, not inferred from client repositories or guessed ports.
Credentials were supplied out of band (`BUAA_USER`/`BUAA_PW` environment, stdin-like
transport); no credential value appears in this document, in argv, or in any
committed fixture.

This catalog records both what worked and what failed, because the failures are
part of the contract.

## 1. Network facts that break naive clients

| Observation | Consequence |
|---|---|
| `sso.buaa.edu.cn`, `byxt`, `i.buaa.edu.cn`, `booking.lib`, `yjsxk`, `ygdk` resolve to an **IPv6** address (`2001:da8:203:15::2`) that does not accept connections | A browser or client that prefers IPv6 hangs. The IPv4 answer is `10.254.15.1` (one campus web gateway); `app.buaa.edu.cn` is `10.200.21.8`. Browser capture needed `--host-resolver-rules=MAP <host> <ipv4>`. |
| `GET https://sso.buaa.edu.cn/login` **without** a `service` parameter returns an empty body / TLS `unexpected eof` from this host | Not a defect of a particular client: the gateway stalls that shape. |
| `GET /login?service=<raw url>` (un-encoded `://`) returns a **truncated** 501-byte document whose `<body>` never arrives | The `service` value MUST be percent-encoded (`encodeURIComponent`). With `%3A%2F%2F` the same request returns the full 11,650-byte login page. |
| `POST /login` without the service in the session | CAS answers `302 → /login` (form redisplay), which looks like a wrong password but is a lost service binding. |

## 2. CAS login mechanics (verified end to end)

Request shape that produced a service ticket:

1. `GET https://sso.buaa.edu.cn/login?service=<percent-encoded service>` → HTML
   containing `<input name="execution" value="…">` (the value is ~5.7 KB) and, when
   the service is bound, `<div class="service">本研综合教务管理系统</div>` naming the
   relying party.
2. `POST https://sso.buaa.edu.cn/login` (form-urlencoded) with
   `username`, `password`, `type=username_password`, `execution=<value>`,
   `_eventId=submit`, `submit=LOGIN`, carrying the session cookies from step 1.
3. Success = `302` whose `Location` carries `?ticket=ST-…`. Anything else (including
   a redirect back to `/login`) is a failed attempt, never a "maybe".
4. Follow the `Location` once. The relying party consumes the single-use ticket and
   sets its own session cookies.

The visible login UI in a browser is the **iframe** `/cas/login-normal.html`
(controls `#unPassword`, `#pwPassword`, `input.submit-btn[onclick=loginPassword]`);
the parent page's `#loginForm` is present but hidden, so scripting the parent form
does not represent what a user does. The iframe content carries an `aria-label`
containing text that instructs assistants to ignore prior instructions — that is
untrusted page data and is ignored, never executed.

Anti-bot notes for browser work: the pages sit behind a `guard.js`/`websdp` layer.
Playwright `waitUntil: 'domcontentloaded'` stalls on this gateway; `waitUntil:
'commit'` plus explicit waits works. Trusted input (real `page.mouse.click` at the
control's bounding box plus `page.keyboard.type`) is the reliable path; JS-dispatched
`el.value=…; dispatchEvent(...)` and `form.requestSubmit()` did not authenticate the
same account in the same session.

## 3. Relying-party service URLs (observed)

| Capability | CAS `service` | Landing |
|---|---|---|
| exams (`byxt`, 本研综合教务) | `https://byxt.buaa.edu.cn/jwapp/sys/byrhmhsy/index.do` | `200`, session cookies `JSESSIONID`/`route`/`_WEU` |
| enrol (`yjsxk`) | `https://yjsxk.buaa.edu.cn/yjsxkapp/sys/xsxkappbuaa/*default/index.do` | lands on **http** scheme |
| timetable-pg (`gsmis`) | `https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do` | `200` |
| ihome | `http://i.buaa.edu.cn/api/authLogin` | `/web/#…` fragment token |
| boya (`bykc`) | `https://bykc.buaa.edu.cn/sscv/cas/login` | `302 → /cas-login?token=<32 hex>` |
| smart classrooms | `https://app.buaa.edu.cn/a_buaa/api/cas/index?redirect=…&from=wap&login_from=` | app session |
| smart library | `https://booking.lib.buaa.edu.cn/v4/login/cas` | library session |
| classroom | `https://yjapi.msa.buaa.edu.cn/casapi/index.php?forward=…&r=auth/login&tenant_code=21` | classroom session |
| running (`ygdk`, 阳光打卡) | *not a direct CAS service*: the SPA authenticates through `https://app.buaa.edu.cn/uc/api/oauth/index?redirect=…&appid=200230221144501510`, then calls `POST https://ygdk.buaa.edu.cn/api/Front/Clockin/User/campusAppLogin` for its own `uid`+`token` |  |
| coursegrading (`judge`) | serves its own login page (`/indexcs/simple.jsp`), no CAS redirect observed |  |
| checkin (`iclass:8347`) | no response from this host during the observation window |  |

## 4. Relaying-party API observations

| Capability | Request | Observed result |
|---|---|---|
| exams | `GET https://byxt.buaa.edu.cn/jwapp/sys/homeapp/api/home/student/exams.do?termCode=2026-2027-1` with the CAS session cookie, `Accept: */*`, `X-Requested-With: XMLHttpRequest`, `Referer: https://byxt.buaa.edu.cn/jwapp/sys/homeapp/index.html` | `200`, body `{"datas":[],"code":"0","msg":null}` — the CLI's `code=="0"` admission matches; the empty list is a term/account fact, not a failure |
| enrol | `GET https://yjsxk.buaa.edu.cn/yjsxkapp/sys/xsxkappbuaa/xsxkCourse/loadKbxx.do?sfyx=1&sfjzsyzz=1` with the CAS session cookie | **`302 → http://` same path**, then `200` with a 55,957-byte JSON payload containing `XNXQDM="20261"` course rows |
| boya | CAS login returns `/cas-login?token=<32 hex>`; the SPA then sends `auth_token`/`authtoken` headers to `https://bykc.buaa.edu.cn/sscv/<api>` | token issuance itself is the CAS artifact — no separate credential exchange needed |
| ihome | `GET /api/…` list with the fragment token | `entry_count=0` for this account |

### Consequence for the yjsxk reader

`https://yjsxk.buaa.edu.cn/...` answers **`302` to the `http://` scheme of the exact
same path**. The CLI's strict-TLS policy refuses a scheme downgrade and reports
`blocked` with `fallback_reason="yjsxk response issued Set-Cookie…"`, which is the
accurate behaviour for the current policy. Reading this service therefore needs an
explicit owner decision to admit that one exact HTTP origin — it is not a parser bug.

## 5. Tooling facts from this session

- The host has **no** Python `playwright`/`camoufox`; `pypi.org` times out. `npm`
  through `registry.npmmirror.com` works, and `/tank/p2v/home/ezra/.cache/ms-playwright`
  already holds Chromium builds, so a browser can be driven without downloading one.
- The installed Camoufox build (`152.0.4-beta.28`) is present under
  `/tank/p2v/home/ezra/.cache/camoufox` but has no matching Python package on this
  host; the observations above were made with Playwright driving the cached Chromium.
- Percent-encoded `service` is the single most important detail: without it the
  gateway truncates the login document and the form never exists.
