import re
import time
from typing import Any, Dict, Optional, Tuple

import requests


_RE_KEY = re.compile(r"(?i)([?&]key=)([^&\s]+)")
_RE_KEY_URLENC = re.compile(r"(?i)(key%3d)([^&\s]+)")
_RE_AUTH_HEADER = re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)")
_RE_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")
_RE_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}")


def redact_sensitive(text: Any) -> str:
    """
    Redact secrets from any text that might end up in GitHub Actions logs or Bpium fields.

    Currently redacts:
    - query param key=... (parser-api)
    - urlencoded key%3d...
    - Authorization: ... (if it ever appears in text)
    - Basic/Bearer tokens (best-effort)
    """
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s
    s = _RE_KEY.sub(r"\1<redacted>", s)
    s = _RE_KEY_URLENC.sub(r"\1<redacted>", s)
    s = _RE_AUTH_HEADER.sub(r"\1<redacted>", s)
    s = _RE_BASIC.sub("Basic <redacted>", s)
    s = _RE_BEARER.sub("Bearer <redacted>", s)
    return s


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str],
    *,
    params: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    timeout: int = 60,
    retries: int = 2,
    backoff: Tuple[int, ...] = (1, 2),
) -> Any:
    """
    requests wrapper that NEVER leaks secrets in exception messages.

    Important: do not use exception chaining ("raise ... from exc") because the original
    requests exception message can contain the full URL with key=... and will be printed
    in GitHub Actions logs.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = session.request(method, url, headers=headers, params=params, json=json_body, timeout=timeout)
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()
        except requests.HTTPError as exc:
            resp = exc.response
            if resp is not None:
                try:
                    snippet = (resp.text or "").replace("\r", " ").replace("\n", " ")[:800]
                except Exception:
                    snippet = "<unavailable>"
                safe_url = redact_sensitive(resp.url)
                raise RuntimeError(
                    f"HTTP {resp.status_code} for {safe_url}; body={redact_sensitive(snippet)!r}"
                )
            # Fallback: no response object (rare)
            raise RuntimeError(f"HTTP error: {redact_sensitive(str(exc))}")
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(backoff[attempt] if attempt < len(backoff) else 2**attempt)
                continue
            raise RuntimeError(f"Request failed: {redact_sensitive(str(exc))}")
    if last_exc:
        raise RuntimeError(f"Request failed: {redact_sensitive(str(last_exc))}")
    raise RuntimeError("request failed without exception")

