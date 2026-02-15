import argparse
import base64
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from pypdf import PdfReader


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_auth_header(login: str, password: str) -> str:
    token = f"{login}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


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
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = session.request(method, url, headers=headers, params=params, json=json_body, timeout=timeout)
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()
        except requests.HTTPError as exc:
            # Make Actions logs self-contained: show response status/url and a small body snippet.
            resp = exc.response
            if resp is not None:
                try:
                    snippet = (resp.text or "").replace("\r", " ").replace("\n", " ")[:800]
                except Exception:
                    snippet = "<unavailable>"
                raise RuntimeError(f"HTTP {resp.status_code} for {resp.url}; body={snippet!r}") from exc
            raise
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(backoff[attempt] if attempt < len(backoff) else 2**attempt)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("request failed without exception")


def parser_api_pdf_download(session: requests.Session, api_key: str, pdf_url: str) -> str:
    url = "https://parser-api.com/parser/arbitr_api/pdf_download"
    params = {"key": api_key, "url": pdf_url}
    data = request_json(session, "GET", url, headers={"Accept": "application/json"}, params=params, timeout=90)
    if not isinstance(data, dict):
        raise RuntimeError(f"parser-api: unexpected response type: {type(data)}")
    if data.get("error") or data.get("error_code"):
        raise RuntimeError(f"parser-api error: {data}")
    if data.get("Success") is not None and int(data.get("Success") or 0) != 1:
        raise RuntimeError(
            "parser-api: Success!=1 (check PARSER_API_KEY subscription/IP limits and that pdf_url is a direct kad.arbitr.ru PDF): "
            + str(data)
        )
    b64 = data.get("pdfContent")
    return "" if b64 is None else str(b64)


def normalize_pdf_base64(b64: str) -> str:
    s = str(b64 or "").strip()
    idx = s.find("base64,")
    if idx >= 0:
        s = s[idx + 7 :]
    s = "".join(s.split())
    return s


def extract_text_from_pdf_base64(b64: str) -> Tuple[str, str]:
    """
    Returns (status, payload):
    - status: ok|empty|error
    - payload: text for ok, '' for empty, error string for error
    """
    s = normalize_pdf_base64(b64)
    if not s:
        return "empty", ""

    try:
        pdf_bytes = base64.b64decode(s, validate=False)
    except Exception as exc:
        return "error", f"base64 decode failed: {exc}"

    if not pdf_bytes.startswith(b"%PDF"):
        return "error", f"decoded bytes do not look like PDF, head={pdf_bytes[:16]!r}"

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        parts = []
        for p in reader.pages:
            parts.append(p.extract_text() or "")
        text = "\n\n".join(parts).strip()
    except Exception as exc:
        return "error", f"pdf text extraction failed: {exc}"

    if not text:
        return "empty", ""
    return "ok", text


def get_record(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_id: str,
    record_id: str,
) -> Dict[str, Any]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records/{record_id}"
    data = request_json(session, "GET", url, headers=headers, timeout=60)
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected record format: {type(data)}")
    return data


def patch_record_values(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_id: str,
    record_id: str,
    values: Dict[str, Any],
) -> Any:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records/{record_id}"
    payload = {"values": values}
    return request_json(session, "PATCH", url, headers=headers, json_body=payload, timeout=60)


def get_value(values: Dict[str, Any], field_id: str) -> Any:
    if field_id in values:
        return values[field_id]
    try:
        i = int(field_id)
    except Exception:
        return None
    return values.get(i)


def main() -> int:
    ap = argparse.ArgumentParser(description="Bpium worker: fill PdfText for one record using parser-api /pdf_download")
    ap.add_argument("--record-id", required=True, help="Bpium record id to process")
    ap.add_argument("--budget", type=int, default=1, help="Max parser-api calls (default 1)")
    ap.add_argument("--force", action="store_true", help="Write even if PdfText already exists")
    ap.add_argument("--dry-run", action="store_true", help="Do not write to Bpium")
    args = ap.parse_args()

    domain = os.getenv("BPIUM_DOMAIN", "").rstrip("/")
    login = os.getenv("BPIUM_LOGIN", "")
    password = os.getenv("BPIUM_PASSWORD", "")
    api_key = os.getenv("PARSER_API_KEY", "")

    if not domain or not login or not password or not api_key:
        print("Missing env vars: BPIUM_DOMAIN, BPIUM_LOGIN, BPIUM_PASSWORD, PARSER_API_KEY", file=sys.stderr)
        return 2

    # GitHub Actions passes unset secrets as empty strings when mapped to env.
    # Treat empty strings as "not set" and use defaults.
    catalog_id = os.getenv("BPIUM_CATALOG_ID") or "45"
    fid_pdf_url = os.getenv("BPIUM_FIELD_PDF_URL") or "7"
    fid_pdf_text = os.getenv("BPIUM_FIELD_PDF_TEXT") or "19"
    fid_pdf_text_fetched_at = os.getenv("BPIUM_FIELD_PDF_TEXT_FETCHED_AT") or "20"
    fid_pdf_text_status = os.getenv("BPIUM_FIELD_PDF_TEXT_STATUS") or "21"
    fid_pdf_text_error = os.getenv("BPIUM_FIELD_PDF_TEXT_ERROR") or "22"

    headers = {
        "Authorization": build_auth_header(login, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    with requests.Session() as s:
        rec = get_record(s, domain, headers, catalog_id, str(args.record_id))
        vals = rec.get("values") if isinstance(rec.get("values"), dict) else {}

        pdf_url = str(get_value(vals, fid_pdf_url) or "").strip()
        if not pdf_url:
            print(json.dumps({"ok": False, "reason": "no_pdf_url"}, ensure_ascii=False))
            return 0

        existing = str(get_value(vals, fid_pdf_text) or "")
        if existing.strip() and not args.force:
            print(json.dumps({"ok": True, "skipped": True, "reason": "already_has_pdftext"}, ensure_ascii=False))
            return 0

        if args.budget < 1:
            print(json.dumps({"ok": False, "reason": "budget_lt_1"}, ensure_ascii=False))
            return 0

        try:
            b64 = parser_api_pdf_download(s, api_key, pdf_url)
            if not b64:
                status, payload = "empty", ""
            else:
                status, payload = extract_text_from_pdf_base64(b64)
        except Exception as exc:
            status, payload = "error", str(exc)

        now = iso_utc_now()
        out_vals: Dict[str, Any] = {
            str(fid_pdf_text_status): status,
            str(fid_pdf_text_fetched_at): now,
            str(fid_pdf_text_error): payload if status == "error" else "",
            str(fid_pdf_text): payload if status == "ok" else "",
        }

        if args.dry_run:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "dryRun": True,
                        "status": status,
                        "textLen": len(payload) if status == "ok" else 0,
                        "error": payload if status == "error" else "",
                    },
                    ensure_ascii=False,
                )
            )
            return 0

        patch_record_values(s, domain, headers, catalog_id, str(args.record_id), out_vals)
        print(
            json.dumps(
                {
                    "ok": True,
                    "status": status,
                    "textLen": len(payload) if status == "ok" else 0,
                    "error": payload if status == "error" else "",
                },
                ensure_ascii=False,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
