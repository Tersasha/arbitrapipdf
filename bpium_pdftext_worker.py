import argparse
import base64
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from pypdf import PdfReader


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_auth_header(login: str, password: str) -> str:
    token = f"{login}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def parse_iso_utc(s: str) -> Optional[datetime]:
    ss = str(s or "").strip()
    if not ss:
        return None
    # Expect our own format: 2026-02-15T12:34:56Z
    try:
        if ss.endswith("Z"):
            return datetime.strptime(ss, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        # Fallback: try to parse timezone-aware ISO (best-effort)
        return datetime.fromisoformat(ss.replace("Z", "+00:00"))
    except Exception:
        return None


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


def get_value(values: Dict[str, Any], field_id: str) -> Any:
    if field_id in values:
        return values[field_id]
    try:
        i = int(field_id)
    except Exception:
        return None
    return values.get(i)


def list_records(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_id: str,
    *,
    limit: int,
    offset: int,
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records"
    data = request_json(session, "GET", url, headers=headers, params={"limit": str(limit), "offset": str(offset)})
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected records list type: {type(data)}")
    return [x for x in data if isinstance(x, dict)]


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


def main() -> int:
    ap = argparse.ArgumentParser(description="Bpium worker: fill PdfText using parser-api /pdf_download")
    ap.add_argument("--record-id", default="", help="Bpium record id to process (if empty, scan catalog)")
    ap.add_argument("--budget", type=int, default=1, help="Max parser-api calls per run (default 1)")
    ap.add_argument("--page-size", type=int, default=100, help="How many Bpium records to fetch per page (default 100)")
    ap.add_argument("--max-scan", type=int, default=2000, help="Max records to scan per run (default 2000)")
    ap.add_argument(
        "--retry-errors",
        action="store_true",
        help="Also retry records with PdfTextStatus=error (with cooldown). Default: false",
    )
    ap.add_argument(
        "--cooldown-hours",
        type=int,
        default=24,
        help="Do not reprocess recently attempted records unless --force (default 24h)",
    )
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
        api_calls = 0
        scanned = 0
        processed = 0
        ok_count = 0
        empty_count = 0
        error_count = 0

        def should_process(vals: Dict[str, Any]) -> Tuple[bool, str]:
            pdf_url = str(get_value(vals, fid_pdf_url) or "").strip()
            if not pdf_url:
                return False, "no_pdf_url"

            existing = str(get_value(vals, fid_pdf_text) or "").strip()
            if existing and not args.force:
                return False, "already_has_pdftext"

            status = str(get_value(vals, fid_pdf_text_status) or "").strip().lower()
            fetched_at = parse_iso_utc(str(get_value(vals, fid_pdf_text_fetched_at) or ""))

            # Default behavior: only fill when PdfText is empty and status is not a known terminal state.
            if not args.force:
                if status == "ok":
                    return False, "status_ok"
                if status == "empty":
                    return False, "status_empty"
                if status == "error" and not args.retry_errors:
                    return False, "status_error_skip"

                if fetched_at is not None and args.cooldown_hours > 0:
                    age_h = (datetime.now(timezone.utc) - fetched_at).total_seconds() / 3600.0
                    if age_h < float(args.cooldown_hours):
                        return False, "cooldown"

            return True, "need_process"

        def process_record(record_id: str, vals: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal api_calls, processed, ok_count, empty_count, error_count

            pdf_url = str(get_value(vals, fid_pdf_url) or "").strip()

            if args.budget < 1:
                return {"ok": False, "reason": "budget_lt_1"}
            if api_calls >= args.budget:
                return {"ok": True, "skipped": True, "reason": "budget_exhausted"}

            processed += 1
            api_calls += 1

            try:
                b64 = parser_api_pdf_download(s, api_key, pdf_url)
                if not b64:
                    status, payload = "empty", ""
                else:
                    status, payload = extract_text_from_pdf_base64(b64)
            except Exception as exc:
                status, payload = "error", str(exc)

            if status == "ok":
                ok_count += 1
            elif status == "empty":
                empty_count += 1
            else:
                error_count += 1

            now = iso_utc_now()
            out_vals: Dict[str, Any] = {
                str(fid_pdf_text_status): status,
                str(fid_pdf_text_fetched_at): now,
                str(fid_pdf_text_error): payload if status == "error" else "",
                str(fid_pdf_text): payload if status == "ok" else "",
            }

            if not args.dry_run:
                patch_record_values(s, domain, headers, catalog_id, str(record_id), out_vals)

            return {"ok": True, "recordId": str(record_id), "status": status, "textLen": len(payload) if status == "ok" else 0, "error": payload if status == "error" else ""}

        if args.record_id:
            rec = get_record(s, domain, headers, catalog_id, str(args.record_id))
            vals = rec.get("values") if isinstance(rec.get("values"), dict) else {}
            scanned = 1
            need, reason = should_process(vals)
            if not need:
                print(json.dumps({"ok": True, "skipped": True, "reason": reason}, ensure_ascii=False))
                return 0
            res = process_record(str(args.record_id), vals)
            res.update({"mode": "single", "scanned": scanned, "processed": processed, "apiCalls": api_calls})
            print(json.dumps(res, ensure_ascii=False))
            return 0

        # Scan mode: iterate catalog and fill only records with empty PdfText (and allowed by policy).
        offset = 0
        while scanned < args.max_scan and api_calls < args.budget:
            page = list_records(s, domain, headers, catalog_id, limit=args.page_size, offset=offset)
            if not page:
                break
            for rec in page:
                if scanned >= args.max_scan or api_calls >= args.budget:
                    break
                scanned += 1
                rid = str(rec.get("id") or "").strip()
                vals = rec.get("values") if isinstance(rec.get("values"), dict) else {}
                need, _reason = should_process(vals)
                if not need:
                    continue
                _ = process_record(rid, vals)
            offset += args.page_size

        print(
            json.dumps(
                {
                    "ok": True,
                    "mode": "scan",
                    "scanned": scanned,
                    "processed": processed,
                    "apiCalls": api_calls,
                    "okCount": ok_count,
                    "emptyCount": empty_count,
                    "errorCount": error_count,
                    "dryRun": bool(args.dry_run),
                },
                ensure_ascii=False,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
