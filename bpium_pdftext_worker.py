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

from bpium_http import redact_sensitive, request_json


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


# request_json is imported from bpium_http to avoid leaking secrets in URL/headers.


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
    view_id: str = "",
    search_text: str = "",
    sort_field: str = "",
    sort_type: str = "",
    filters_json: str = "",
    fields_json: str = "",
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records"
    params: Dict[str, str] = {"limit": str(limit), "offset": str(offset)}
    if view_id:
        params["viewId"] = str(view_id)
    if search_text:
        params["searchText"] = str(search_text)
    if sort_field:
        params["sortField"] = str(sort_field)
    if sort_type:
        params["sortType"] = str(sort_type)
    if filters_json:
        params["filters"] = str(filters_json)
    if fields_json:
        params["fields"] = str(fields_json)

    data = request_json(session, "GET", url, headers=headers, params=params)
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
    ap.add_argument("--view-id", default="", help="Bpium viewId (optional; see docs.bpium.ru Records)")
    ap.add_argument("--search-text", default="", help="Bpium searchText (optional)")
    ap.add_argument("--sort-field", default="id", help="Bpium sortField (default: id)")
    ap.add_argument("--sort-type", default="-1", help="Bpium sortType (1 asc, -1 desc; default: -1)")
    ap.add_argument(
        "--filters-json",
        default="",
        help='Bpium filters JSON (string). If empty in scan mode, a safe default is used to only scan records with PdfUrl containing "kad.arbitr.ru".',
    )
    ap.add_argument(
        "--fields-json",
        default="",
        help="Bpium fields JSON array (string). If empty, worker requests only the needed field ids.",
    )
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
    ap.add_argument(
        "--debug-skip-reasons",
        action="store_true",
        help="Include skip reason statistics in scan mode output (default: false)",
    )
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

    # Scan query options (can be overridden via env to avoid editing workflow inputs).
    scan_view_id = os.getenv("BPIUM_VIEW_ID") or str(args.view_id or "")
    scan_search_text = os.getenv("BPIUM_SEARCH_TEXT") or str(args.search_text or "")
    scan_sort_field = os.getenv("BPIUM_SORT_FIELD") or str(args.sort_field or "")
    scan_sort_type = os.getenv("BPIUM_SORT_TYPE") or str(args.sort_type or "")
    scan_filters_json = os.getenv("BPIUM_FILTERS_JSON") or str(args.filters_json or "")
    scan_fields_json = os.getenv("BPIUM_FIELDS_JSON") or str(args.fields_json or "")

    if not scan_fields_json:
        # Reduce payload size: only ask for fields we need in should_process/process_record.
        scan_fields_json = json.dumps(
            [str(fid_pdf_url), str(fid_pdf_text), str(fid_pdf_text_fetched_at), str(fid_pdf_text_status), str(fid_pdf_text_error)]
        )

    if not scan_filters_json and not args.record_id:
        # Default filter for this project: only records that have PdfUrl pointing to kad.arbitr.ru.
        # This prevents wasting scan budget on records without PDFs.
        scan_filters_json = json.dumps({str(fid_pdf_url): "kad.arbitr.ru"})

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
        pages_fetched = 0
        skip_counts: Dict[str, int] = {}
        min_id: Optional[int] = None
        max_id: Optional[int] = None

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
            existing_text = str(get_value(vals, fid_pdf_text) or "").strip()
            existing_status = str(get_value(vals, fid_pdf_text_status) or "").strip().lower()

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
                status, payload = "error", redact_sensitive(str(exc))

            if status == "ok":
                ok_count += 1
            elif status == "empty":
                empty_count += 1
            else:
                error_count += 1

            now = iso_utc_now()
            out_vals: Dict[str, Any] = {
                str(fid_pdf_text_fetched_at): now,
                str(fid_pdf_text_error): payload if status == "error" else "",
            }
            if status == "ok" and payload:
                out_vals[str(fid_pdf_text_status)] = "ok"
                out_vals[str(fid_pdf_text)] = payload
            else:
                # Do not erase previously successful PdfText on transient errors.
                if not existing_text:
                    out_vals[str(fid_pdf_text_status)] = status
                elif existing_status != "ok":
                    out_vals[str(fid_pdf_text_status)] = status

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
        # Note: budget controls *parser-api* calls (processing), not Bpium scanning.
        # This allows running with --budget 0 to "scan-only" (no parser-api calls), useful for debugging.
        while scanned < args.max_scan:
            page = list_records(
                s,
                domain,
                headers,
                catalog_id,
                limit=args.page_size,
                offset=offset,
                view_id=scan_view_id,
                search_text=scan_search_text,
                sort_field=scan_sort_field,
                sort_type=scan_sort_type,
                filters_json=scan_filters_json,
                fields_json=scan_fields_json,
            )
            if not page:
                break
            pages_fetched += 1
            for rec in page:
                if scanned >= args.max_scan:
                    break
                scanned += 1
                rid = str(rec.get("id") or "").strip()
                try:
                    rid_i = int(rid)
                    min_id = rid_i if min_id is None else min(min_id, rid_i)
                    max_id = rid_i if max_id is None else max(max_id, rid_i)
                except Exception:
                    pass
                vals = rec.get("values") if isinstance(rec.get("values"), dict) else {}
                need, _reason = should_process(vals)
                if not need:
                    if args.debug_skip_reasons:
                        skip_counts[_reason] = skip_counts.get(_reason, 0) + 1
                    continue
                # Budget can be 0 => scan-only
                if args.budget < 1 or api_calls >= args.budget:
                    if args.debug_skip_reasons:
                        skip_counts["budget_exhausted"] = skip_counts.get("budget_exhausted", 0) + 1
                    # Stop early to avoid rescanning the whole catalog when we already hit the budget.
                    # This keeps scheduled runs cheap.
                    break
                _ = process_record(rid, vals)
            offset += args.page_size
            if args.budget >= 1 and api_calls >= args.budget:
                break

        out: Dict[str, Any] = {
            "ok": True,
            "mode": "scan",
            "catalogId": str(catalog_id),
            "scanned": scanned,
            "processed": processed,
            "apiCalls": api_calls,
            "okCount": ok_count,
            "emptyCount": empty_count,
            "errorCount": error_count,
            "pagesFetched": pages_fetched,
            "scannedIdRange": {"minId": min_id, "maxId": max_id},
            "scanQuery": {
                "viewId": scan_view_id,
                "searchText": scan_search_text,
                "sortField": scan_sort_field,
                "sortType": scan_sort_type,
                "filters": scan_filters_json,
                "fields": scan_fields_json,
            },
            "dryRun": bool(args.dry_run),
        }
        if args.debug_skip_reasons:
            out["skipReasons"] = dict(sorted(skip_counts.items(), key=lambda kv: (-kv[1], kv[0])))
        print(json.dumps(out, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
