#!/usr/bin/env python3
"""Real-Camoufox graduate-timetable session helper for buaa-cli.

The Rust caller embeds this file and runs it as ``python3 -c <source>`` with
one strict timetable session JSON document on stdin and a minimal
environment. Exactly one JSON envelope is written to the original stdout;
diagnostics (if any) go to stderr only. No credential, cookie, storage state,
ticket, fingerprint payload, raw trace or init body is ever exported, and
nothing is persisted to disk by this helper.

Successful output:
    {"schema_version":1,"result":"read","http_status":N,
     "content_type":<str|null>,"body_base64":"..."}
Errors:
    {"schema_version":1,"result":"error","error":<code>,
     "message":<fixed safe text>[,"http_status":N]}

Only error codes accepted by the caller's camoufox_failure() mapping are
emitted: auth_latched, challenge_requires_human, network_error,
authentication_unconfirmed, credential_echo, response_safety_unreviewed,
invalid_input, cooldown and unavailable.
"""

import base64
import hashlib
import json
import os
import re
import signal
import sys
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Contract constants (mirrored from src/timetable.rs).
# ---------------------------------------------------------------------------

MAX_INPUT = 65536
MAX_BODY = 8 * 1024 * 1024
MAX_ISSUED_COOKIES = 64
MAX_SECRETS = 256
OVERALL_DEADLINE_SECONDS = 600

PORTAL_URL = "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do"
PAGE_URL = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/*default/index.do"
INIT_URL = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/wdkcb/initXsxx.do"
XSKB_URL = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/bykb/loadXskbData.do"
SSO_HOST = "sso.buaa.edu.cn"
GSMIS_HOST = "gsmis.buaa.edu.cn"

NAV_TIMEOUT_MS = 60000
WAIT_TIMEOUT_MS = 30000
POST_WAIT_SECONDS = 90
FETCH_TIMEOUT_MS = 45000

DENIAL_MARKERS = (
    "登录失效",
    "请重新登录",
    "未登录",
    "用户名或密码错误",
    "账号或密码错误",
    "用户名密码错误",
    "密码错误",
    "账户或密码错误",
    "认证失败",
)
CHALLENGE_MARKERS = (
    "captcha",
    "challenge",
    "turnstile",
    "verificationcode",
    "verification-code",
    "verification_code",
    "verification code",
    "验证码",
    "校验码",
)

_ERROR_MESSAGES = {
    "auth_latched": "CAS authentication or session was rejected",
    "challenge_requires_human": "authentication requires a human challenge",
    "network_error": "timetable transport failed",
    "authentication_unconfirmed": "CAS handoff or student context could not be confirmed",
    "credential_echo": "response carries credential or cookie material",
    "response_safety_unreviewed": "response could not be screened completely",
    "invalid_input": "timetable session input does not match the xskb contract",
    "unavailable": "Camoufox runtime is unavailable",
    "cooldown": "the service deferred the timetable session",
}


class HelperFailure(Exception):
    """One terminal, fixed-message failure. Never carries secret material.

    ``retry_after``/``header_challenge`` pass observed response-header facts
    to the caller; they never contain secret material (Retry-After values
    are screened before being retained).
    """

    def __init__(self, code, http_status=None, retry_after=None, header_challenge=False):
        super().__init__(code)
        self.code = code if code in _ERROR_MESSAGES else "unavailable"
        self.http_status = http_status
        self.retry_after = retry_after
        self.header_challenge = bool(header_challenge)


def _error(code, http_status=None, retry_after=None, header_challenge=False):
    return HelperFailure(code, http_status, retry_after, header_challenge)


# ---------------------------------------------------------------------------
# Strict input admission: no credentials ever enter a generic value tree
# that is logged, and unknown/duplicate members are refused.
# ---------------------------------------------------------------------------


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _strict_string(value):
    return isinstance(value, str) and not isinstance(value, bool)


def _valid_secret(value):
    # Mirrors SsoCredentials::new / valid_secret: non-empty, <=1024 bytes,
    # no control characters.
    return (
        _strict_string(value)
        and value != ""
        and len(value.encode("utf-8")) <= 1024
        and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)
    )


def parse_input(raw):
    if len(raw) > MAX_INPUT:
        raise _error("invalid_input")
    try:
        text = raw.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()),
        )
    except Exception:
        raise _error("invalid_input")
    if not isinstance(document, dict):
        raise _error("invalid_input")
    required = {"authorized", "username", "password", "intent", "read", "backend"}
    if set(document) != required:
        raise _error("invalid_input")
    if document["authorized"] is not True:
        raise _error("invalid_input")
    username = document["username"]
    password = document["password"]
    if not _valid_secret(username) or not _valid_secret(password):
        raise _error("invalid_input")
    if document["intent"] != "LOGIN " + username + " timetable":
        raise _error("invalid_input")
    read = document["read"]
    if not isinstance(read, dict) or set(read) != {"operation", "enabled", "xnxqdm"}:
        raise _error("invalid_input")
    if read["operation"] != "xskb" or read["enabled"] is not True:
        raise _error("invalid_input")
    term = read["xnxqdm"]
    if not _strict_string(term) or len(term) != 5 or not term.isascii() or not term.isdigit():
        raise _error("invalid_input")
    if document["backend"] != "camoufox":
        raise _error("invalid_input")
    return username, password, term


# ---------------------------------------------------------------------------
# Invocation-only secret material. Values never leave this process.
# ---------------------------------------------------------------------------


def _valid_cookie_name(value):
    if not value or len(value) > 256:
        return False
    return all(
        ch.isascii() and (ch.isalnum() or ch in "!#$%&'*+-.^_`|~") for ch in value
    )


def _valid_cookie_value(value):
    if len(value) > 4096:
        return False
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return False
        value = value[1:-1]
    if '"' in value:
        return False
    allowed = set(range(0x21, 0x22)) | set(range(0x23, 0x2C)) | set(range(0x2D, 0x3B))
    allowed |= set(range(0x3C, 0x5C)) | set(range(0x5D, 0x7F))
    return all(ord(ch) in allowed for ch in value)


class SecretJar:
    """All browser-issued session material, held only for the echo screen.

    Secrets never leave this process. ``_live`` tracks the current cookie
    set only so that retired (deleted/replaced) values can be detected and
    kept in the guard; a retired value remains secret forever.
    """

    def __init__(self, username, password):
        self.username = username
        self.secrets = []
        self._seen = set()
        self._live = {}
        self.complete = True
        self.add(username)
        self.add(password)

    def add(self, value):
        if not isinstance(value, str) or value == "":
            return
        if value in self._seen:
            return
        if len(self.secrets) >= MAX_SECRETS:
            self.complete = False
            return
        self._seen.add(value)
        self.secrets.append(value)

    def incomplete(self):
        """Mark the jar unscreened when a response's declared cookie or
        header set could not be observed at all (e.g. headers_array()
        failed). An empty observed set is complete; a failed read is not."""
        self.complete = False

    def _retire_gone(self, names_now):
        """Values that vanished from the live set stay in the guard."""
        for name, retired in self._live.items():
            if name not in names_now:
                for value in retired:
                    self.add(value)
                    self.add(name + "=" + value)
        self._live = {name: values for name, values in self._live.items() if name in names_now}

    def _admit_pair(self, name, value, live):
        """One reviewed name=value declaration; mirrors IssuedCookies::absorb."""
        if not _strict_string(name) or not _strict_string(value):
            self.complete = False
            return
        name = name.strip()
        value = value.strip()
        if not _valid_cookie_name(name) or not _valid_cookie_value(value):
            self.complete = False
            return
        unquoted = value
        if len(unquoted) >= 2 and unquoted.startswith('"') and unquoted.endswith('"'):
            unquoted = unquoted[1:-1]
        if live is not None:
            live.setdefault(name, set())
        if unquoted == "":
            # A deletion, not a secret. Any earlier value for this name has
            # already been absorbed and stays in the guard.
            if live is not None:
                live.pop(name, None)
            return
        self.add(value)
        self.add(unquoted)
        self.add(name + "=" + value)
        if unquoted != value:
            self.add(name + "=" + unquoted)
        if live is not None:
            live[name].add(value)

    def absorb_declarations(self, declarations):
        """Absorb raw Set-Cookie declaration texts from one response, hop by
        hop. A declaration count over the bound, missing '=', or an invalid
        name/value leaves the jar incomplete rather than exporting an
        unscreened body."""
        if declarations is None:
            return
        if len(declarations) > MAX_ISSUED_COOKIES:
            self.complete = False
            return
        for declaration in declarations:
            if not isinstance(declaration, str):
                self.complete = False
                continue
            pair = declaration.split(";", 1)[0]
            name, sep, value = pair.partition("=")
            if not sep:
                self.complete = False
                continue
            self._admit_pair(name, value, self._live)

    def absorb(self, context):
        """Absorb every cookie the fresh context currently holds.

        Replaced/expired/path-excluded values seen earlier stay in the jar:
        they were added by previous absorptions and are never removed, and
        this snapshot diff retires values the jar no longer reports.
        """
        try:
            cookies = context.cookies()
        except Exception:
            self.complete = False
            return
        if len(cookies) > MAX_ISSUED_COOKIES:
            self.complete = False
            return
        live = {}
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if not _strict_string(name):
                self.complete = False
                continue
            self._admit_pair(name, value, live)
        self._retire_gone(set(live))
        self._live = live

    def without_expected_identity(self):
        """Exclude only the CAS username for the never-exported init XH."""
        clone = object.__new__(SecretJar)
        clone.username = self.username
        clone.secrets = [value for value in self.secrets if value != self.username]
        clone._seen = set(clone.secrets)
        clone._live = {name: set(values) for name, values in self._live.items()}
        clone.complete = self.complete
        return clone

    def remember_transmitted(self, context, urls):
        try:
            cookies = context.cookies(urls)
        except Exception:
            self.complete = False
            return
        pairs = []
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if _strict_string(name) and _strict_string(value) and value != "":
                pairs.append(name + "=" + value)
        if pairs:
            self.add("; ".join(pairs))


# ---------------------------------------------------------------------------
# carries_secret: literal, JSON-escaped, base64 (std/url-safe, padded or not)
# and percent/form-decoded spellings, searched in every valid UTF-8 chunk.
# ---------------------------------------------------------------------------

_SERDE_CONTROL = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _serde_escape(value):
    out = []
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code in _SERDE_CONTROL:
            out.append(_SERDE_CONTROL[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    return "".join(out)


def _needles(secret):
    encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    needles = [secret, encoded.rstrip("=")]
    if any(byte in (0x20,) or byte < 0x20 or byte in (0x22, 0x5C) for byte in secret.encode("utf-8")):
        needles.append(_serde_escape(secret))
    if "+" in encoded or "/" in encoded:
        needles.append(base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii").rstrip("="))
    return [n for n in needles if n]


def _chunk_matches(part, needles):
    # Needles are valid UTF-8, so no match can straddle an invalid sequence.
    # Searching the replacement-decoded view is equivalent to Rust's
    # valid-chunk scan for these needles.
    text = part.decode("utf-8", "replace")
    return any(needle in text for needle in needles)


def _percent_decode(data, plus_as_space):
    out = bytearray()
    index = 0
    length = len(data)
    while index < length:
        byte = data[index]
        if byte == 0x25 and index + 2 < length:
            try:
                out.append(int(data[index + 1:index + 3].decode("ascii"), 16))
                index += 3
                continue
            except ValueError:
                pass
        if plus_as_space and byte == 0x2B:
            out.append(0x20)
        else:
            out.append(byte)
        index += 1
    return bytes(out)


def carries_secret(candidate, secret):
    if secret == "" or len(candidate) < len(secret.encode("utf-8")):
        return False
    needles = _needles(secret)
    if _chunk_matches(candidate, needles):
        return True
    has_percent = 0x25 in candidate
    has_plus = 0x2B in candidate
    if not has_percent and not has_plus:
        return False
    if has_percent and _chunk_matches(_percent_decode(candidate, False), needles):
        return True
    if has_plus and _chunk_matches(_percent_decode(candidate, True), needles):
        return True
    # form_urlencoded::parse equivalent: & separated, first = splits,
    # percent decoding with + as space.
    for field in candidate.split(b"&"):
        name, sep, value = field.partition(b"=")
        for part in (name, value if sep else b""):
            if _chunk_matches(_percent_decode(part, True), needles):
                return True
    return False


def _any_secret(candidate, jar):
    return any(carries_secret(candidate, secret) for secret in jar.secrets)


# ---------------------------------------------------------------------------
# Body screening: raw bytes, decoded JSON members/strings/scalars, and a
# per-literal fallback for bodies a strict decoder rejects.
# ---------------------------------------------------------------------------


def _strict_json(body):
    return json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_no_duplicates,
        parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()),
    )


def _value_echo(value, jar):
    if isinstance(value, str):
        return _any_secret(value.encode("utf-8"), jar)
    if isinstance(value, bool) or value is None:
        return _any_secret(json.dumps(value).encode("ascii"), jar)
    if isinstance(value, (int, float)):
        return _any_secret(json.dumps(value).encode("ascii"), jar)
    if isinstance(value, list):
        return any(_value_echo(item, jar) for item in value)
    if isinstance(value, dict):
        return any(
            _any_secret(key.encode("utf-8"), jar) or _value_echo(item, jar)
            for key, item in value.items()
        )
    return False


def _escaped_literal_screening(body, jar):
    cursor = 0
    unreviewable = False
    length = len(body)
    while cursor < length:
        if body[cursor] != 0x22:
            cursor += 1
            continue
        opening = cursor
        cursor += 1
        escaped = False
        terminated = False
        while cursor < length:
            byte = body[cursor]
            if byte == 0x5C:
                escaped = True
                cursor += 2
            elif byte == 0x22:
                terminated = True
                break
            else:
                cursor += 1
        if not terminated:
            if escaped:
                unreviewable = True
            break
        if escaped:
            try:
                decoded = json.loads(body[opening:cursor + 1].decode("utf-8"))
                if not isinstance(decoded, str):
                    unreviewable = True
                elif _any_secret(decoded.encode("utf-8"), jar):
                    return "echo"
            except Exception:
                unreviewable = True
        cursor += 1
    return "unreviewable" if unreviewable else "clear"


def screen_body(body, jar):
    """Returns (echo: bool, unreviewable: bool), mirroring decoded_body_screening."""
    if _any_secret(body, jar):
        return True, False
    try:
        value = _strict_json(body)
    except Exception:
        verdict = _escaped_literal_screening(body, jar)
        return verdict == "echo", verdict == "unreviewable"
    return _value_echo(value, jar), False


# ---------------------------------------------------------------------------
# A conservative challenge screen for bodies. It only ever refuses; the
# caller in Rust performs its own full DOM assessment on the exported body.
# ---------------------------------------------------------------------------


def _mime_parts(content_type):
    if not content_type:
        return None
    essence = content_type.split(";", 1)[0].strip(" \t")
    kind, sep, subtype = essence.partition("/")
    if not sep or not kind or not subtype or "*" in kind or "*" in subtype:
        return None
    token = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
    if not token.match(kind) or not token.match(subtype):
        return None
    return kind.lower(), subtype.lower()


def _html_charset(content_type):
    declared = None
    remaining = content_type.split(";", 1)
    if len(remaining) != 2:
        return "absent"
    rest = remaining[1]
    for parameter in rest.split(";"):
        name, sep, value = parameter.partition("=")
        if not sep:
            continue
        if name.strip(" \t").lower() != "charset":
            continue
        value = value.strip(" \t").strip('"')
        if not value:
            return "invalid"
        if declared is not None and declared.lower() != value.lower():
            return "invalid"
        declared = value
    if declared is None:
        return "absent"
    return "utf8" if declared.lower() in ("utf-8", "utf8") else "other"


def _looks_like_html(body):
    data = body
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.lstrip(b"\t\n\x0c\r ")
    lowered = data[:16].lower()
    return lowered.startswith(b"<!doctype") or lowered.startswith(b"<html") or lowered.startswith(b"<!--")


def _strip_inert_html(text):
    # Drop comments and raw-text/inert payloads before looking for markers.
    text = re.sub(r"(?s)<!--.*?-->", "", text)
    text = re.sub(r"(?s)<(script|style|template|noscript)\b.*?</\1\s*>", "", text, flags=re.I)
    return text


def _challenge_text_hit(text):
    for marker in CHALLENGE_MARKERS:
        if any(ord(ch) > 0x7F for ch in marker):
            if marker in text:
                return True
    tags = re.findall(r"(?s)<[^>]*>", text)
    for tag in tags:
        folded = tag.lower()
        for marker in CHALLENGE_MARKERS:
            if marker.isascii() and marker in folded:
                return True
    return False


def assess_challenge(body, content_type):
    parts = _mime_parts(content_type)
    if parts is None:
        return "unreviewed"
    kind, subtype = parts
    if kind == "application" and subtype == "xhtml+xml":
        return "unreviewed"
    if kind == "text" and subtype == "html":
        charset = _html_charset(content_type)
        if charset in ("other", "invalid"):
            return "unreviewed"
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("utf-8", "replace")
        return "detected" if _challenge_text_hit(_strip_inert_html(text)) else "clear"
    is_json = (
        kind == "application"
        and subtype != "vnd.github.raw+json"
        and (subtype == "json" or subtype.endswith("+json"))
    )
    if is_json:
        try:
            body.decode("utf-8")
            _strict_json(body)
        except Exception:
            return "unreviewed"
        # Valid JSON carries data strings, never active challenge controls.
        return "clear"
    if _looks_like_html(body[:4096]):
        return "unreviewed"
    if kind == "text":
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return "clear"
        return "detected" if _challenge_text_hit(_strip_inert_html(text)) else "clear"
    return "clear"


def challenge_header(name, value):
    """Mirrors net::challenge_header for one decoded header line."""
    if not _strict_string(value):
        return False
    value = value.strip(" \t")
    lname = name.lower()
    if lname == "cf-mitigated":
        return value.lower() == "challenge"
    return (
        lname in ("x-captcha", "x-challenge") or lname.startswith("cf-chl-")
    ) and value != ""


def _header_pairs(headers):
    """Normalize Playwright headers_array() dicts or 'k: v' strings into
    (lower-name, value) pairs, unfolding newline-folded multi-declarations."""
    pairs = []
    for entry in headers or []:
        if isinstance(entry, dict):
            name = entry.get("name")
            value = entry.get("value")
        elif isinstance(entry, str):
            name, sep, value = entry.partition(":")
            if not sep:
                continue
        else:
            continue
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        lname = name.strip(" \t").lower()
        for line in value.split("\n"):
            pairs.append((lname, line.strip(" \t\r")))
    return pairs


def header_facts(declarations):
    """content_type, retry_after, header_challenge from one response's
    declared headers. All values are screened before use or retention."""
    content_type = None
    retry_after = None
    challenged = False
    for lname, value in _header_pairs(declarations):
        if lname == "content-type" and content_type is None:
            content_type = value
        elif lname == "retry-after" and retry_after is None:
            retry_after = value
        elif challenge_header(lname, value):
            challenged = True
    return content_type, retry_after, challenged


def session_denied(body):
    try:
        value = json.loads(body.decode("utf-8"))
    except Exception:
        return False
    if not isinstance(value, dict):
        return False
    for key in ("message", "msg", "m"):
        message = value.get(key)
        if isinstance(message, str) and any(marker in message for marker in DENIAL_MARKERS[:3]):
            return True
    return False


def screen_response(
    body,
    content_type,
    jar,
    status=None,
    retry_after=None,
    header_challenge=False,
    expected_identity_echo=False,
):
    """Shared refusal pipeline. Order: echo, unreviewed, challenge, denial.

    Every refusal carries the response's http_status and observed header
    facts so the caller keeps native parity.
    """
    if expected_identity_echo:
        jar = jar.without_expected_identity()
    echo, unreviewable = screen_body(body, jar)
    if echo:
        raise _error("credential_echo", status)
    if unreviewable or not jar.complete:
        raise _error("response_safety_unreviewed", status)
    if content_type and _any_secret(content_type.encode("utf-8"), jar):
        raise _error("credential_echo", status)
    if header_challenge or assess_challenge(body, content_type) == "detected":
        raise _error(
            "challenge_requires_human", status, retry_after, header_challenge
        )
    if session_denied(body):
        raise _error("auth_latched", status)


# ---------------------------------------------------------------------------
# Browser-side bounded fetch. Runs in the page main world (mw: prefix), with
# an abort timer and a hard 8 MiB cap. Only base64 bytes cross back.
# ---------------------------------------------------------------------------

_FETCH_TEMPLATE = r"""
mw:(async () => {
  const url = %(url)s;
  const method = %(method)s;
  const form = %(form)s;
  const referer = %(referer)s;
  const limit = %(limit)d;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), %(timeout)d);
  try {
    const options = {
      method: method,
      credentials: 'same-origin',
      redirect: 'manual',
      referrer: referer,
      headers: {
        'Accept': %(accept)s
      },
      signal: controller.signal
    };
    if (method === 'POST') {
      options.headers['X-Requested-With'] = 'XMLHttpRequest';
      options.headers['Content-Type'] =
        'application/x-www-form-urlencoded; charset=UTF-8';
      options.body = new URLSearchParams(form).toString();
    }
    const response = await fetch(url, options);
    const status = response.status;
    const headersArray = Array.from(response.headers.entries()).map(
      (pair) => pair[0] + ': ' + pair[1]
    );
    let setCookie = [];
    if (typeof response.headers.getSetCookie === 'function') {
      setCookie = response.headers.getSetCookie();
    }
    if (response.type === 'opaqueredirect' || status === 0 ||
        (status >= 300 && status < 400)) {
      // Redirects are never followed silently, and a response with no
      // observable status is not a read. The caller admits destinations
      // explicitly; a missing Location is reported, never guessed.
      return {
        status: status,
        headersArray: headersArray,
        setCookie: setCookie,
        redirected: true,
        redirectLocation: response.headers.get('location') || null,
        oversized: false,
        bodyBase64: null
      };
    }
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit) {
      controller.abort();
      return {
        status: status,
        headersArray: headersArray,
        setCookie: setCookie,
        redirectLocation: null,
        oversized: true,
        declaredLength: declared,
        bodyBase64: null
      };
    }
    const chunks = [];
    let total = 0;
    if (response.body) {
      const reader = response.body.getReader();
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        total += item.value.byteLength;
        if (total > limit) {
          controller.abort();
          return {
            status: status,
            headersArray: headersArray,
            setCookie: setCookie,
            redirectLocation: null,
            oversized: true,
            declaredLength: null,
            bodyBase64: null
          };
        }
        chunks.push(item.value);
      }
    } else {
      const buffer = new Uint8Array(await response.arrayBuffer());
      total = buffer.byteLength;
      if (total > limit) {
        return {
          status: status,
          headersArray: headersArray,
          setCookie: setCookie,
          redirectLocation: null,
          oversized: true,
          declaredLength: null,
          bodyBase64: null
        };
      }
      chunks.push(buffer);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    }
    return {
      status: status,
      headersArray: headersArray,
      setCookie: setCookie,
      redirectLocation: null,
      oversized: false,
      bodyBase64: btoa(binary)
    };
  } finally {
    clearTimeout(timer);
  }
})()
"""


# ---------------------------------------------------------------------------
# Terminal read outcome. A refused body is never exported: the Read variant
# carries safe metadata only (declared content type when unechoed, length,
# sha256, header facts, the recognized-denial flag and the refusal reason)
# so the caller can build sensitive_response_withheld/session_expired with
# native parity.
# ---------------------------------------------------------------------------


def _read_envelope(
    status,
    content_type,
    jar,
    body=None,
    withheld_body=None,
    retry_after=None,
    header_challenge=False,
    denied=False,
    reason=None,
    declared_length=None,
):
    """A terminal read outcome. ``body`` is exported as base64 (admitted
    reads only). ``withheld_body`` contributes real byte_length and sha256
    metadata but never the bytes — used for refused bodies, mirroring the
    native withheld() which retains sha256 and length."""
    safe_content_type = content_type
    if safe_content_type and _any_secret(safe_content_type.encode("utf-8"), jar):
        safe_content_type = None
    if retry_after is not None and (
        not isinstance(retry_after, str)
        or _any_secret(retry_after.encode("utf-8"), jar)
    ):
        retry_after = None
    provenance = body if body is not None else withheld_body
    byte_length = len(provenance) if provenance is not None else declared_length
    sha256 = (
        hashlib.sha256(provenance).hexdigest() if provenance is not None else None
    )
    return {
        "schema_version": 1,
        "result": "read",
        "http_status": status,
        "content_type": safe_content_type,
        "body_base64": base64.b64encode(body).decode("ascii") if body is not None else None,
        "body_sha256": sha256,
        "body_byte_length": byte_length,
        "header_challenge": bool(header_challenge),
        "retry_after": retry_after,
        "denied": bool(denied),
        "refusal_reason": reason,
    }


def _bounded_request(page, url, jar, method="POST", form=None, referer=None, accept=None):
    """One bounded same-origin request. Never follows a redirect implicitly,
    aborts reads over the limit without buffering them, and returns a fact
    dict for the caller. Bodies never leave this process unsolicited."""
    source = _FETCH_TEMPLATE % {
        "url": json.dumps(url),
        "method": json.dumps(method),
        "form": json.dumps(form or {}),
        "referer": json.dumps(referer) if referer else "undefined",
        "accept": json.dumps(accept or "application/json, text/javascript, */*; q=0.01"),
        "limit": MAX_BODY,
        "timeout": FETCH_TIMEOUT_MS,
    }
    jar.remember_transmitted(page.context, [url])
    try:
        result = page.evaluate(source)
    except HelperFailure:
        raise
    except Exception:
        raise _error("network_error")
    if not isinstance(result, dict):
        raise _error("network_error")
    status = result.get("status")
    headers_array = result.get("headersArray")
    if isinstance(headers_array, list) and all(
        isinstance(line, str) for line in headers_array
    ):
        content_type, retry_after, header_challenge = header_facts(headers_array)
    else:
        content_type, retry_after, header_challenge = None, None, False
        if not isinstance(status, int) or status != 0:
            jar.incomplete()
    jar.absorb_declarations(result.get("setCookie"))
    jar.absorb(page.context)
    # An opaque redirect or a response with no observable status is a
    # handoff failure, never a read or a network error: classified before
    # the normal status range check, and absent Location is never guessed.
    if result.get("redirected") or (isinstance(status, int) and status == 0):
        raise _error(
            "authentication_unconfirmed",
            status if isinstance(status, int) and 100 <= status <= 599 else None,
            retry_after,
            header_challenge,
        )
    if not isinstance(status, int) or not 100 <= status <= 599:
        raise _error("network_error")
    if not isinstance(headers_array, list):
        raise _error("response_safety_unreviewed", status)
    if result.get("redirectLocation") is not None:
        raise _error(
            "authentication_unconfirmed", status, retry_after, header_challenge
        )
    encoded = result.get("bodyBase64")
    if result.get("oversized"):
        return {
            "status": status,
            "content_type": content_type,
            "retry_after": retry_after,
            "header_challenge": header_challenge,
            "oversized": True,
            "declared_length": result.get("declaredLength")
            if isinstance(result.get("declaredLength"), int)
            else None,
            "body": None,
        }
    if not isinstance(encoded, str):
        raise _error("response_safety_unreviewed", status, retry_after, header_challenge)
    try:
        body = base64.b64decode(encoded, validate=True)
    except Exception:
        raise _error("response_safety_unreviewed", status, retry_after, header_challenge)
    if len(body) > MAX_BODY:
        return {
            "status": status,
            "content_type": content_type,
            "retry_after": retry_after,
            "header_challenge": header_challenge,
            "oversized": True,
            "declared_length": len(body),
            "body": None,
        }
    return {
        "status": status,
        "content_type": content_type,
        "retry_after": retry_after,
        "header_challenge": header_challenge,
        "oversized": False,
        "declared_length": len(body),
        "body": body,
    }


# ---------------------------------------------------------------------------
# Visible CAS interaction. Real pointer/keyboard only; no fill(), no value
# assignment, no fabricated telemetry, no challenge bypass, no retry.
# ---------------------------------------------------------------------------

_PAGE_PROBE = r"""
() => {
  const markers = ['captcha', 'challenge', 'turnstile', 'verificationcode',
    'verification-code', 'verification_code', '验证码', '校验码'];
  const denials = ['登录失效', '请重新登录', '未登录', '用户名或密码错误',
    '账号或密码错误', '用户名密码错误', '密码错误', '账户或密码错误', '认证失败'];
  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden';
  };
  let challenge = false;
  let denial = false;
  for (const el of document.querySelectorAll('input,textarea,select,button,iframe,div,span,img')) {
    if (el.matches('script,style,template,noscript')) continue;
    const attrs = [];
    for (const name of ['id', 'name', 'class', 'src', 'alt', 'title', 'action']) {
      const value = el.getAttribute && el.getAttribute(name);
      if (value) attrs.push(value.toLowerCase());
    }
    if (attrs.some((value) => markers.some((m) => value.includes(m)))) {
      if (visible(el)) challenge = true;
    }
    if ((el.matches('button,span,div,label') && el.children.length === 0)) {
      const text = (el.textContent || '').trim();
      if (text.length > 0 && text.length <= 120) {
        if (denials.some((m) => text.includes(m))) denial = true;
        if (visible(el) && (text.includes('验证码') || text.includes('校验码'))) challenge = true;
      }
    }
  }
  return {challenge: challenge, denial: denial};
}
"""


def _probe(page):
    challenge = False
    denial = False
    frames = [page.main_frame]
    for frame in page.frames:
        if frame != page.main_frame and frame.url.startswith("https://" + SSO_HOST + "/"):
            frames.append(frame)
    for frame in frames:
        try:
            facts = frame.evaluate(_PAGE_PROBE)
        except Exception:
            continue
        if isinstance(facts, dict):
            challenge = challenge or bool(facts.get("challenge"))
            denial = denial or bool(facts.get("denial"))
    return challenge, denial


def _login_frame(page):
    for frame in page.frames:
        if frame.url.startswith("https://" + SSO_HOST + "/cas/login-normal.html"):
            return frame
    return None


def _type_exactly(page, locator, value):
    box = locator.bounding_box(timeout=WAIT_TIMEOUT_MS)
    if not box:
        raise _error("authentication_unconfirmed")
    page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    page.keyboard.type(value, delay=45)
    try:
        observed = locator.input_value(timeout=WAIT_TIMEOUT_MS)
    except Exception:
        raise _error("authentication_unconfirmed")
    if observed != value:
        # Never submit a mistyped credential. This is an input correction,
        # not another authentication attempt.
        raise _error("authentication_unconfirmed")


# ---------------------------------------------------------------------------
# Navigation constraint. Every document navigation (including frame loads,
# 307/308 POST continuations and ticket-bearing redirects) is admitted
# before it is sent: only the reviewed SSO host and the GSMIS host may ever
# be navigated to. A request outside that envelope is aborted before the
# wire, never sent and inspected afterwards.
# ---------------------------------------------------------------------------


_SSO_NAV_PATHS = ("/login", "/cas/login-normal.html")
_GSMIS_NAV_PATHS = (
    "/gsapp/sys/yjsemaphome/portal/index.do",
    "/gsapp/sys/wdkbapp/*default/index.do",
)


def _allowed_navigation(url):
    """Only the reviewed chain's document URLs may ever be navigated to:
    the SSO login route and its visible login-normal frame, then the GSMIS
    portal landing and the wdkbapp application document. Sub-resource and
    XHR requests are outside this gate (they are not navigations)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        return False
    if parts.scheme != "https" or not parts.hostname:
        return False
    if parts.username or parts.password or parts.port not in (None, 443):
        return False
    host = parts.hostname.lower()
    if host == SSO_HOST:
        return parts.path in _SSO_NAV_PATHS
    if host == GSMIS_HOST:
        return parts.path in _GSMIS_NAV_PATHS
    return False


def install_guards(context, flow):
    """Install the pre-send navigation admit list. Any document navigation
    whose destination is not on the reviewed SSO/GSMIS envelope is aborted
    before it reaches the wire; sub-resource requests pass through."""

    def guard(route):
        try:
            request = route.request
            if request.is_navigation_request():
                url = request.url
                if not _allowed_navigation(url):
                    flow["nav_violated"] = True
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
        except HelperFailure:
            raise
        except Exception:
            # Never fail open on a navigation guard error.
            try:
                if route.request.is_navigation_request():
                    flow["nav_violated"] = True
                    route.abort("blockedbyclient")
                    return
            except Exception:
                pass
        try:
            route.continue_()
        except Exception:
            pass

    context.route("**/*", guard)


def _record_on(page, jar, flow):
    def record(response):
        try:
            request = response.request
            url = response.url
            navigation = request.is_navigation_request()
        except Exception:
            return
        try:
            headers = response.headers_array()
        except Exception:
            # The declaration set could not be observed at all: the body is
            # unscreenable, never assumed complete.
            jar.incomplete()
            headers = []
        pairs = _header_pairs(headers)
        set_cookie = [value for lname, value in pairs if lname == "set-cookie"]
        location = None
        for lname, value in pairs:
            if lname == "location":
                location = value
                break
        jar.absorb_declarations(set_cookie)
        _, retry_after, challenged = header_facts(headers)
        if challenged:
            flow["header_challenge"] = True
        if retry_after:
            flow["retry_after"] = retry_after
        if not navigation:
            return
        try:
            if (
                request.method == "POST"
                and response.url.startswith("https://" + SSO_HOST + "/login")
            ):
                flow["login_post_status"] = response.status
                flow["login_post_ticket"] = bool(
                    location and "ticket=" in location
                )
        except Exception:
            return

    page.on("response", record)


def perform_login(page, jar, flow, username, password):
    _record_on(page, jar, flow)
    try:
        page.goto(PORTAL_URL, wait_until="commit", timeout=NAV_TIMEOUT_MS)
    except Exception:
        raise _error("network_error")
    jar.absorb(page.context)
    if flow.get("nav_violated"):
        raise _error("authentication_unconfirmed")

    frame = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        frame = _login_frame(page)
        if frame is not None:
            break
        challenge, denial = _probe(page)
        if challenge or flow.get("header_challenge"):
            raise _error("challenge_requires_human")
        if flow.get("nav_violated"):
            raise _error("authentication_unconfirmed")
        time.sleep(0.25)
    if frame is None:
        challenge, _ = _probe(page)
        if challenge or flow.get("header_challenge"):
            raise _error("challenge_requires_human")
        raise _error("authentication_unconfirmed")

    user_field = frame.locator("#unPassword")
    password_field = frame.locator("#pwPassword")
    try:
        user_field.wait_for(state="visible", timeout=WAIT_TIMEOUT_MS)
        password_field.wait_for(state="visible", timeout=WAIT_TIMEOUT_MS)
    except Exception:
        challenge, _ = _probe(page)
        if challenge:
            raise _error("challenge_requires_human")
        raise _error("authentication_unconfirmed")

    # The intended visible frame and its controls exist; challenge-check the
    # exact login frame before any credential is typed.
    try:
        facts = frame.evaluate(_PAGE_PROBE)
    except Exception:
        facts = None
    if isinstance(facts, dict) and facts.get("challenge"):
        raise _error("challenge_requires_human")
    challenge, _ = _probe(page)
    if challenge:
        raise _error("challenge_requires_human")

    # Constrain the credential destination before typing, on the real chain:
    # the iframe has no form of its own — Enter runs the frame's
    # loginPassword() which calls parent.doLogin(), which fills and submits
    # the parent's #loginForm. Verify exactly that topology: both controls
    # are formless (.form === null), parent.doLogin is a function, and the
    # parent form's action resolves to the reviewed sso /login route.
    topology_deadline = time.monotonic() + WAIT_TIMEOUT_MS / 1000
    while True:
        try:
            topology = frame.evaluate(
                "mw:() => {"
                " const u = document.querySelector('#unPassword');"
                " const p = document.querySelector('#pwPassword');"
                " const parent = window.parent;"
                " const f = parent && parent.document"
                "   ? parent.document.querySelector('#loginForm') : null;"
                " return {"
                "   unformless: !!(u && u.form === null),"
                "   pwformless: !!(p && p.form === null),"
                "   doLogin: typeof (parent && parent.doLogin) === 'function',"
                "   action: f ? (f.getAttribute('action') || '') : ''"
                " };"
                " }"
            )
        except Exception:
            topology = None
        if isinstance(topology, dict):
            action = topology.get("action")
            try:
                resolved = urllib.parse.urljoin(page.url, action if isinstance(action, str) else "")
                action_host = urllib.parse.urlsplit(resolved).hostname
                action_path = urllib.parse.urlsplit(resolved).path
            except Exception:
                action_host = None
                action_path = None
            if (
                topology.get("unformless")
                and topology.get("pwformless")
                and topology.get("doLogin")
                and action_host == SSO_HOST
                and action_path == "/login"
            ):
                break
        if time.monotonic() >= topology_deadline or flow.get("nav_violated"):
            raise _error("authentication_unconfirmed")
        time.sleep(0.1)

    # Visible, real pointer/keyboard input, exact per-field readback, Enter.
    _type_exactly(page, user_field, username)
    _type_exactly(page, password_field, password)
    jar.remember_transmitted(page.context, ["https://" + SSO_HOST + "/login"])
    try:
        password_field.press("Enter", timeout=WAIT_TIMEOUT_MS)
    except Exception:
        raise _error("authentication_unconfirmed")

    deadline = time.monotonic() + POST_WAIT_SECONDS
    while time.monotonic() < deadline:
        host = urllib.parse.urlsplit(page.url).hostname
        if host == GSMIS_HOST:
            break
        if flow.get("nav_violated"):
            raise _error("authentication_unconfirmed")
        status = flow.get("login_post_status")
        if status in (401, 403):
            raise _error("auth_latched", status)
        if status == 302 and not flow.get("login_post_ticket"):
            raise _error("auth_latched", status)
        if status == 429:
            raise _error(
                "cooldown", status, flow.get("retry_after"), flow.get("header_challenge", False)
            )
        if flow.get("header_challenge"):
            raise _error("challenge_requires_human")
        if host == SSO_HOST:
            challenge, denial = _probe(page)
            if challenge:
                raise _error("challenge_requires_human")
            if denial:
                raise _error("auth_latched")
        time.sleep(0.25)
    else:
        challenge, denial = _probe(page)
        if challenge or flow.get("header_challenge"):
            raise _error("challenge_requires_human")
        if denial:
            raise _error("auth_latched")
        raise _error("authentication_unconfirmed")

    if urllib.parse.urlsplit(page.url).hostname != GSMIS_HOST:
        raise _error("authentication_unconfirmed")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=WAIT_TIMEOUT_MS)
    except Exception:
        pass
    jar.absorb(page.context)


def enter_application(page, jar):
    """The wdkbapp application document, read as one bounded same-origin GET.

    The fetch streams through the shared AbortController reader, so an
    oversized body aborts at the bound instead of being buffered. A
    transport/read failure is network_error, an over-limit body is a
    body_limit terminal outcome, and neither is presented as an
    authentication result. The page keeps its portal identity; the document
    itself is request-level, exactly like the native GET."""
    result = _bounded_request(
        page,
        PAGE_URL,
        jar,
        method="GET",
        referer=PORTAL_URL,
        accept="text/html",
    )
    status = result["status"]
    content_type = result["content_type"]
    retry_after = result["retry_after"]
    header_challenge = result["header_challenge"]
    if result["oversized"]:
        return _read_envelope(
            status,
            content_type,
            jar,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="body_limit",
            declared_length=result["declared_length"],
        )
    body = result["body"]
    screen_response(
        body,
        content_type,
        jar,
        status=status,
        retry_after=retry_after,
        header_challenge=header_challenge,
        expected_identity_echo=True,
    )
    if status == 429 or retry_after is not None:
        raise _error("cooldown", status, retry_after, header_challenge)
    if status != 200:
        raise _error("authentication_unconfirmed", status, retry_after)
    mime = content_type.split(";", 1)[0].strip().lower() if content_type else None
    if mime != "text/html" or not body.strip():
        raise _error("authentication_unconfirmed", status, retry_after)
    return None


def read_timetable(page, jar, term):
    init = _bounded_request(
        page, INIT_URL, jar, form={"XH": ""}, referer=PAGE_URL
    )
    status = init["status"]
    retry_after = init["retry_after"]
    header_challenge = init["header_challenge"]
    if init["oversized"]:
        return _read_envelope(
            status,
            init["content_type"],
            jar,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="body_limit",
            declared_length=init["declared_length"],
        )
    init_body = init["body"]
    # The init body is screened and validated in memory only; never exported.
    screen_response(
        init_body,
        init["content_type"],
        jar,
        status=status,
        retry_after=retry_after,
        header_challenge=header_challenge,
        expected_identity_echo=True,
    )
    if status == 429 or retry_after is not None:
        raise _error("cooldown", status, retry_after, header_challenge)
    if not 200 <= status < 300:
        raise _error("authentication_unconfirmed", status, retry_after)
    try:
        context = _strict_json(init_body)
    except Exception:
        raise _error("authentication_unconfirmed", status, retry_after)
    rows = context.get("data") if isinstance(context, dict) else None
    if not isinstance(rows, list) or not rows:
        raise _error("authentication_unconfirmed", status, retry_after)
    for row in rows:
        if not isinstance(row, dict):
            raise _error("authentication_unconfirmed", status, retry_after)
        identity = row.get("XH")
        if (
            not isinstance(identity, str)
            or identity == ""
            or len(identity.encode("utf-8")) > 128
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in identity)
        ):
            raise _error("authentication_unconfirmed", status, retry_after)
    del init_body

    read = _bounded_request(
        page,
        XSKB_URL,
        jar,
        form={"ZC": "", "XNXQDM": term, "XH": "", "XQDM": ""},
        referer=PAGE_URL,
    )
    status = read["status"]
    content_type = read["content_type"]
    retry_after = read["retry_after"]
    header_challenge = read["header_challenge"]
    if read["oversized"]:
        return _read_envelope(
            status,
            content_type,
            jar,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="body_limit",
            declared_length=read["declared_length"],
        )
    body = read["body"]
    echo, unreviewable = screen_body(body, jar)
    if echo:
        return _read_envelope(
            status,
            content_type,
            jar,
            withheld_body=body,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="credential_echo",
        )
    if unreviewable or not jar.complete:
        return _read_envelope(
            status,
            content_type,
            jar,
            withheld_body=body,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="response_safety_unreviewed",
        )
    if content_type and _any_secret(content_type.encode("utf-8"), jar):
        return _read_envelope(
            status,
            content_type,
            jar,
            withheld_body=body,
            retry_after=retry_after,
            header_challenge=header_challenge,
            reason="credential_echo",
        )
    challenge = header_challenge or assess_challenge(body, content_type) == "detected"
    if challenge:
        return _read_envelope(
            status,
            content_type,
            jar,
            withheld_body=body,
            retry_after=retry_after,
            header_challenge=True,
            reason="challenge_requires_human",
        )
    denied = session_denied(body)
    if denied:
        return _read_envelope(
            status,
            content_type,
            jar,
            withheld_body=body,
            retry_after=retry_after,
            header_challenge=header_challenge,
            denied=True,
            reason="session_denied",
        )
    return _read_envelope(
        status,
        content_type,
        jar,
        body=body,
        retry_after=retry_after,
        header_challenge=header_challenge,
    )


# ---------------------------------------------------------------------------
# SDK selection: read-only multiversion config, active_version under
# INSTALL_DIR, version.json and an executable pkgman.LAUNCH_FILE. No
# get_active_path/camoufox_path, no downloads, no config mutation.
# ---------------------------------------------------------------------------


def select_executable():
    from camoufox import multiversion, pkgman

    config = multiversion.load_config()
    if not isinstance(config, dict):
        raise _error("unavailable")
    active = config.get("active_version")
    if not isinstance(active, str) or not active:
        raise _error("unavailable")
    install_dir = pkgman.INSTALL_DIR
    root = os.path.realpath(str(install_dir))
    candidate = os.path.realpath(os.path.join(str(install_dir), active))
    if candidate != root and not candidate.startswith(root + os.sep):
        raise _error("unavailable")
    version_file = os.path.join(candidate, "version.json")
    if not os.path.isfile(version_file):
        raise _error("unavailable")
    try:
        with open(version_file, "rb") as handle:
            metadata = json.loads(handle.read(65536).decode("utf-8"))
        if not isinstance(metadata, dict):
            raise ValueError()
    except Exception:
        raise _error("unavailable")
    launch_name = pkgman.LAUNCH_FILE[pkgman.OS_NAME]
    executable = os.path.realpath(os.path.join(candidate, launch_name))
    if executable != root and not executable.startswith(root + os.sep):
        raise _error("unavailable")
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise _error("unavailable")
    return executable


def run(username, password, term):
    executable = select_executable()
    runtime_cache = os.environ.get("BUAA_CAMOUFOX_XDG_CACHE_HOME")
    if runtime_cache is not None:
        try:
            if not os.path.isabs(runtime_cache) or os.path.islink(runtime_cache):
                raise ValueError()
            metadata = os.stat(runtime_cache)
            if not os.path.isdir(runtime_cache) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError()
        except Exception:
            raise _error("unavailable")
        # SDK selection above remains bound to the original installation. Only
        # the browser's runtime cache is redirected to this private directory.
        os.environ["XDG_CACHE_HOME"] = runtime_cache
    from camoufox import DefaultAddons
    from camoufox.sync_api import Camoufox

    browser = None
    context = None
    try:
        with Camoufox(
            headless=False,
            executable_path=executable,
            geoip=False,
            addons=[],
            exclude_addons=list(DefaultAddons),
            main_world_eval=True,
            persistent_context=False,
        ) as browser:
            # A fresh, non-persistent, strict-TLS context. No storage state
            # is loaded or exported, no cache is reused, no proxy is set.
            context = browser.new_context(ignore_https_errors=False)
            context.set_default_timeout(WAIT_TIMEOUT_MS)
            page = context.new_page()
            jar = SecretJar(username, password)
            flow = {"nav_violated": False}
            install_guards(context, flow)
            perform_login(page, jar, flow, username, password)
            entry = enter_application(page, jar)
            if entry is not None:
                return entry
            return read_timetable(page, jar, term)
    except HelperFailure:
        raise
    except Exception:
        raise _error("unavailable")
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


def main():
    # Keep the contract channel clean: redirect the process-level stdout to
    # stderr for any library noise, retaining the original fd for the single
    # JSON envelope.
    try:
        contract_fd = os.dup(1)
        os.dup2(2, 1)
    except OSError:
        contract_fd = None
    result = None

    def _deadline(_signum, _frame):
        raise _error("network_error")

    try:
        signal.signal(signal.SIGALRM, _deadline)
        signal.alarm(OVERALL_DEADLINE_SECONDS)
        try:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        except Exception:
            raise _error("invalid_input")
        username, password, term = parse_input(raw)
        try:
            result = run(username, password, term)
        finally:
            password = None
    except HelperFailure as failure:
        result = {
            "schema_version": 1,
            "result": "error",
            "error": failure.code,
            "message": _ERROR_MESSAGES[failure.code],
        }
        if failure.http_status is not None:
            result["http_status"] = failure.http_status
        if failure.retry_after is not None:
            result["retry_after"] = failure.retry_after
        if failure.header_challenge:
            result["header_challenge"] = True
    except Exception:
        result = {
            "schema_version": 1,
            "result": "error",
            "error": "unavailable",
            "message": _ERROR_MESSAGES["unavailable"],
        }
    finally:
        try:
            signal.alarm(0)
        except Exception:
            pass
    payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if contract_fd is not None:
        os.write(contract_fd, payload)
        os.close(contract_fd)
    else:
        sys.__stdout__.buffer.write(payload)
        sys.__stdout__.buffer.flush()


main()
