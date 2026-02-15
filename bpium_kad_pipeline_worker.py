import argparse
import base64
import calendar
import io
import json
import os
import re
import sys
import time
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from pypdf import PdfReader

from bpium_http import redact_sensitive, request_json


PARSER_API_BASE = "https://parser-api.com/parser/arbitr_api"


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_auth_header(login: str, password: str) -> str:
    token = f"{login}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def as_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def get_value(values: Dict[str, Any], field_id: str) -> Any:
    # Bpium can return keys as strings or ints.
    if field_id in values:
        return values[field_id]
    try:
        i = int(field_id)
    except Exception:
        return None
    return values.get(i)


def has_value(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        return v.strip() != ""
    if isinstance(v, list):
        return len(v) > 0
    if isinstance(v, dict):
        return len(v) > 0
    return True


def is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is False or v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def digits_only(s: str) -> str:
    return re.sub(r"\D+", "", str(s or ""))


def parse_iso_utc(s: str) -> Optional[datetime]:
    ss = str(s or "").strip()
    if not ss:
        return None
    try:
        if ss.endswith("Z"):
            return datetime.strptime(ss, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(ss.replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_date_to_yyyy_mm_dd(v: Any) -> str:
    # Supports: YYYY-MM-DD, ISO datetime, or dict-like wrappers.
    if isinstance(v, dict):
        for k in ("value", "date", "text"):
            if k in v:
                return normalize_date_to_yyyy_mm_dd(v.get(k))
        return ""

    s = str(v or "").strip()
    if not s:
        return ""

    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return s

    dt = parse_iso_utc(s)
    if dt is not None:
        return dt.date().isoformat()

    try:
        dt2 = datetime.fromisoformat(s)
        return dt2.date().isoformat()
    except Exception:
        return ""


def date_minus_months(d: date, months: int) -> date:
    if months <= 0:
        return d
    y = d.year
    m = d.month - months
    while m <= 0:
        m += 12
        y -= 1
    last_day = calendar.monthrange(y, m)[1]
    return date(y, m, min(d.day, last_day))


#
# request_json is imported from bpium_http to avoid leaking secrets in URL/headers.
#


def bpium_list_records(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_id: str,
    *,
    limit: int,
    offset: int,
    view_id: str = "",
    search_text: str = "",
    sort_field: str = "id",
    sort_type: str = "-1",
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

    data = request_json(session, "GET", url, headers=headers, params=params, timeout=60)
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected records list type: {type(data)}")
    return [x for x in data if isinstance(x, dict)]


def bpium_get_record(
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


def bpium_patch_record_values(
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


def bpium_create_record(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_id: str,
    values: Dict[str, Any],
) -> Dict[str, Any]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records"
    payload = {"values": values}
    data = request_json(session, "POST", url, headers=headers, json_body=payload, timeout=60)
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected create record response: {type(data)}")
    return data


def parser_api_search(
    session: requests.Session,
    api_key: str,
    *,
    inn: str,
    page: int,
    date_from: str,
    date_to: str = "",
) -> Dict[str, Any]:
    url = f"{PARSER_API_BASE}/search"
    params: Dict[str, str] = {"key": api_key, "Inn": inn, "page": str(page)}
    if date_from:
        params["DateFrom"] = date_from
    if date_to:
        params["DateTo"] = date_to
    data = request_json(session, "GET", url, headers={"Accept": "application/json"}, params=params, timeout=90)
    if not isinstance(data, dict):
        raise RuntimeError(f"parser-api /search: unexpected response type: {type(data)}")
    if data.get("error") or data.get("error_code"):
        raise RuntimeError(f"parser-api /search error: {data}")
    if data.get("Success") is not None and int(data.get("Success") or 0) != 1:
        raise RuntimeError(f"parser-api /search: Success!=1: {data}")
    return data


def parser_api_details_by_id(session: requests.Session, api_key: str, case_id: str) -> Dict[str, Any]:
    url = f"{PARSER_API_BASE}/details_by_id"
    params = {"key": api_key, "CaseId": case_id}
    data = request_json(session, "GET", url, headers={"Accept": "application/json"}, params=params, timeout=90)
    if not isinstance(data, dict):
        raise RuntimeError(f"parser-api /details_by_id: unexpected response type: {type(data)}")
    if data.get("error") or data.get("error_code"):
        raise RuntimeError(f"parser-api /details_by_id error: {data}")
    if data.get("Success") is not None and int(data.get("Success") or 0) != 1:
        raise RuntimeError(f"parser-api /details_by_id: Success!=1: {data}")
    return data


def parser_api_pdf_download(session: requests.Session, api_key: str, pdf_url: str) -> str:
    url = f"{PARSER_API_BASE}/pdf_download"
    params = {"key": api_key, "url": pdf_url}
    data = request_json(session, "GET", url, headers={"Accept": "application/json"}, params=params, timeout=90)
    if not isinstance(data, dict):
        raise RuntimeError(f"parser-api /pdf_download: unexpected response type: {type(data)}")
    if data.get("error") or data.get("error_code"):
        raise RuntimeError(f"parser-api /pdf_download error: {data}")
    if data.get("Success") is not None and int(data.get("Success") or 0) != 1:
        raise RuntimeError(f"parser-api /pdf_download: Success!=1: {data}")
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
    """Returns (status, payload): ok|empty|error."""
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
        parts: List[str] = []
        for p in reader.pages:
            parts.append(p.extract_text() or "")
        text = "\n\n".join(parts).strip()
    except Exception as exc:
        return "error", f"pdf text extraction failed: {exc}"
    if not text:
        return "empty", ""
    return "ok", text


def looks_like_pdf_url(s: str) -> bool:
    ss = str(s or "").strip().lower()
    if not ss:
        return False
    if "kad.arbitr.ru" not in ss:
        return False
    if ".pdf" in ss:
        return True
    if "/pdfdocument/" in ss:
        return True
    return False


def extract_pdf_url_from_details_json_bfs(details: Any, *, max_nodes: int = 3000) -> str:
    q: List[Any] = [details]
    seen = 0
    while q and seen < max_nodes:
        node = q.pop(0)
        seen += 1
        if isinstance(node, str):
            if looks_like_pdf_url(node):
                return node.strip()
            continue
        if isinstance(node, dict):
            for v in node.values():
                q.append(v)
            continue
        if isinstance(node, list):
            for v in node:
                q.append(v)
            continue
    return ""


def load_cursor_from_lastreqlog(
    raw: str, *, date_from: str, rolling_months: int, rolling_max_pages: int
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "v": 1,
        "mode": "backfill",
        "backfill": {"page": 1, "dateFrom": date_from},
        "rolling": {"months": rolling_months, "maxPages": rolling_max_pages},
        "last": {},
    }
    s = str(raw or "").strip()
    if not s:
        return out
    try:
        data = json.loads(s)
    except Exception:
        return out
    if not isinstance(data, dict):
        return out

    mode = str(data.get("mode") or "").strip().lower()
    if mode in {"backfill", "rolling"}:
        out["mode"] = mode

    bf = data.get("backfill")
    if isinstance(bf, dict):
        try:
            p = int(bf.get("page") or 1)
        except Exception:
            p = 1
        out["backfill"]["page"] = max(1, p)
        # Always override with current 44:22 to keep contract stable.
        out["backfill"]["dateFrom"] = date_from

    # Always override rolling config from inputs.
    out["rolling"]["months"] = rolling_months
    out["rolling"]["maxPages"] = rolling_max_pages

    last = data.get("last")
    if isinstance(last, dict):
        out["last"] = last

    return out


def cursor_to_json(cursor: Dict[str, Any]) -> str:
    return json.dumps(cursor, ensure_ascii=False, separators=(",", ":"))


def find_results_record_by_case_id(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    catalog_45: str,
    fid_case_id: str,
    case_id: str,
) -> Optional[Dict[str, Any]]:
    filters_json = json.dumps({str(fid_case_id): str(case_id)})
    fields_json = json.dumps([str(fid_case_id)])
    page = bpium_list_records(
        session,
        base_url,
        headers,
        catalog_45,
        limit=5,
        offset=0,
        sort_field="id",
        sort_type="-1",
        filters_json=filters_json,
        fields_json=fields_json,
    )
    for rec in page:
        vals = as_dict(rec.get("values"))
        if str(get_value(vals, fid_case_id) or "").strip() == str(case_id).strip():
            return rec
    return None


def upsert_case_to_catalog_45(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    *,
    catalog_45: str,
    fields_45: Dict[str, str],
    inn: str,
    case: Dict[str, Any],
    source: str,
    search_meta: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    fid_inn = fields_45["inn"]
    fid_case_id = fields_45["case_id"]
    fid_case_number = fields_45["case_number"]
    fid_court = fields_45["court"]
    fid_start_date = fields_45["start_date"]
    fid_created_at = fields_45["created_at"]
    fid_source = fields_45["source"]
    fid_search_json = fields_45["search_json"]
    fid_case_type = fields_45["case_type"]

    case_id = str(case.get("CaseId") or "").strip()
    rec = find_results_record_by_case_id(session, base_url, headers, catalog_45, fid_case_id, case_id)

    desired: Dict[str, Any] = {
        str(fid_inn): inn,
        str(fid_case_id): case_id,
        str(fid_case_number): str(case.get("CaseNumber") or ""),
        str(fid_court): str(case.get("Court") or ""),
        str(fid_start_date): str(case.get("StartDate") or ""),
        str(fid_case_type): str(case.get("CaseType") or ""),
        str(fid_source): source,
        str(fid_search_json): json.dumps({"meta": search_meta, "case": case}, ensure_ascii=False),
    }

    if rec is None:
        desired[str(fid_created_at)] = iso_utc_now()
        if dry_run:
            return {"id": "<dry>", "values": desired, "created": True}
        return bpium_create_record(session, base_url, headers, catalog_45, desired)

    rid = str(rec.get("id") or rec.get("recordId") or "").strip()
    vals = as_dict(rec.get("values"))

    patch: Dict[str, Any] = {}
    for k, v in desired.items():
        if not has_value(get_value(vals, str(k))) and has_value(v):
            patch[str(k)] = v

    if patch and not dry_run:
        bpium_patch_record_values(session, base_url, headers, catalog_45, rid, patch)

    if patch:
        merged = dict(vals)
        merged.update(patch)
        rec = dict(rec)
        rec["values"] = merged
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bpium kad pipeline worker: catalog 44 (INN) -> catalog 45 (cases + PdfText) via parser-api"
    )
    ap.add_argument("--track-record-id", default="", help="Bpium catalog 44 record id to process (optional)")
    ap.add_argument("--max-tracks-per-run", type=int, default=1, help="How many tracking records to process per run")
    ap.add_argument("--max-parser-api-calls", type=int, default=15, help="Max parser-api calls per run")
    ap.add_argument("--max-cases-per-track", type=int, default=50, help="Max cases to upsert per tracking record")
    ap.add_argument("--rolling-max-pages", type=int, default=3, help="How many pages to scan in rolling mode")
    ap.add_argument("--dry-run", action="store_true", help="Do not write to Bpium")
    ap.add_argument("--debug", action="store_true", help="Verbose JSON output")
    args = ap.parse_args()

    domain = os.getenv("BPIUM_DOMAIN", "").rstrip("/")
    login = os.getenv("BPIUM_LOGIN", "")
    password = os.getenv("BPIUM_PASSWORD", "")
    api_key = os.getenv("PARSER_API_KEY", "")

    if not domain or not login or not password or not api_key:
        print("Missing env vars: BPIUM_DOMAIN, BPIUM_LOGIN, BPIUM_PASSWORD, PARSER_API_KEY", file=sys.stderr)
        return 2

    cat_44 = os.getenv("BPIUM_TRACKING_CATALOG_ID") or "44"
    cat_45 = os.getenv("BPIUM_RESULTS_CATALOG_ID") or "45"

    # Catalog 44 fields
    f44_inn = os.getenv("BPIUM_44_INN") or "14"
    f44_sync_enabled = os.getenv("BPIUM_44_SYNC_ENABLED") or "16"
    f44_last_sync_at = os.getenv("BPIUM_44_LAST_SYNC_AT") or "17"
    f44_last_sync_status = os.getenv("BPIUM_44_LAST_SYNC_STATUS") or "18"
    f44_last_sync_error = os.getenv("BPIUM_44_LAST_SYNC_ERROR") or "19"
    f44_last_req_count = os.getenv("BPIUM_44_LAST_REQ_COUNT") or "10"
    f44_last_req_log = os.getenv("BPIUM_44_LAST_REQ_LOG") or "11"
    f44_last_req_at = os.getenv("BPIUM_44_LAST_REQ_AT") or "12"
    f44_search_from = os.getenv("BPIUM_44_SEARCH_FROM") or "22"

    # Catalog 45 fields
    fields_45 = {
        "inn": os.getenv("BPIUM_45_INN") or "2",
        "case_id": os.getenv("BPIUM_45_CASE_ID") or "3",
        "case_number": os.getenv("BPIUM_45_CASE_NUMBER") or "4",
        "court": os.getenv("BPIUM_45_COURT") or "5",
        "start_date": os.getenv("BPIUM_45_START_DATE") or "6",
        "pdf_url": os.getenv("BPIUM_45_PDF_URL") or "7",
        "details_fetched_at": os.getenv("BPIUM_45_DETAILS_FETCHED_AT") or "9",
        "created_at": os.getenv("BPIUM_45_CREATED_AT") or "10",
        "source": os.getenv("BPIUM_45_SOURCE") or "11",
        "search_json": os.getenv("BPIUM_45_SEARCH_JSON") or "12",
        "details_json": os.getenv("BPIUM_45_DETAILS_JSON") or "13",
        "case_type": os.getenv("BPIUM_45_CASE_TYPE") or "14",
        "pdf_text": os.getenv("BPIUM_45_PDF_TEXT") or "19",
        "pdf_text_fetched_at": os.getenv("BPIUM_45_PDF_TEXT_FETCHED_AT") or "20",
        "pdf_text_status": os.getenv("BPIUM_45_PDF_TEXT_STATUS") or "21",
        "pdf_text_error": os.getenv("BPIUM_45_PDF_TEXT_ERROR") or "22",
    }

    source = os.getenv("PIPELINE_SOURCE") or "parser-api/kad"
    rolling_months = int(os.getenv("PIPELINE_ROLLING_MONTHS") or "6")
    rolling_max_pages = int(args.rolling_max_pages)

    headers = {
        "Authorization": build_auth_header(login, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    api_calls_total = 0
    tracks_scanned = 0
    tracks_processed = 0

    out_summary: Dict[str, Any] = {
        "ok": True,
        "mode": "pipeline",
        "tracks": {"scanned": 0, "processed": 0},
        "apiCalls": 0,
        "detailsCalls": 0,
        "pdfCalls": 0,
        "casesUpserted": 0,
        "pdfOk": 0,
        "pdfEmpty": 0,
        "pdfErr": 0,
        "dryRun": bool(args.dry_run),
        "updatedAt": iso_utc_now(),
    }

    with requests.Session() as s:
        track_records: List[Dict[str, Any]] = []
        if args.track_record_id:
            track_records = [bpium_get_record(s, domain, headers, cat_44, str(args.track_record_id))]
        else:
            offset = 0
            page_size = 200
            while len(track_records) < int(args.max_tracks_per_run):
                page = bpium_list_records(
                    s,
                    domain,
                    headers,
                    cat_44,
                    limit=page_size,
                    offset=offset,
                    sort_field="id",
                    sort_type="-1",
                    fields_json=json.dumps([f44_inn, f44_sync_enabled, f44_last_req_log, f44_search_from]),
                )
                if not page:
                    break
                for rec in page:
                    tracks_scanned += 1
                    vals = as_dict(rec.get("values"))
                    if not is_truthy(get_value(vals, f44_sync_enabled)):
                        continue
                    inn = digits_only(str(get_value(vals, f44_inn) or ""))
                    if len(inn) not in (10, 12):
                        continue
                    track_records.append(rec)
                    if len(track_records) >= int(args.max_tracks_per_run):
                        break
                offset += page_size

        out_summary["tracks"]["scanned"] = tracks_scanned

        for trec in track_records:
            if api_calls_total >= int(args.max_parser_api_calls):
                break
            tracks_processed += 1

            trid = str(trec.get("id") or trec.get("recordId") or "").strip()
            tvals = as_dict(trec.get("values"))

            inn_digits = digits_only(str(get_value(tvals, f44_inn) or ""))
            date_from_backfill = normalize_date_to_yyyy_mm_dd(get_value(tvals, f44_search_from))

            per_track_api_calls = 0
            per_track_cases_upserted = 0
            per_track_pdf_ok = 0
            per_track_pdf_empty = 0
            per_track_pdf_err = 0
            last_error = ""

            raw_cursor = str(get_value(tvals, f44_last_req_log) or "")
            cursor = load_cursor_from_lastreqlog(
                raw_cursor,
                date_from=date_from_backfill,
                rolling_months=rolling_months,
                rolling_max_pages=rolling_max_pages,
            )

            if not date_from_backfill:
                last_error = f"missing SearchFromDate (catalog 44 field {f44_search_from})"
                cursor["last"] = {
                    "apiCalls": 0,
                    "casesUpserted": 0,
                    "pdfOk": 0,
                    "pdfEmpty": 0,
                    "pdfErr": 1,
                    "updatedAt": iso_utc_now(),
                    "error": last_error,
                }
                if not args.dry_run and trid:
                    bpium_patch_record_values(
                        s,
                        domain,
                        headers,
                        cat_44,
                        trid,
                        {
                            f44_last_sync_at: iso_utc_now(),
                            f44_last_req_at: iso_utc_now(),
                            f44_last_req_count: "0",
                            f44_last_req_log: cursor_to_json(cursor),
                            f44_last_sync_status: "error: missing SearchFromDate",
                            f44_last_sync_error: last_error,
                        },
                    )
                continue

            mode = str(cursor.get("mode") or "backfill").strip().lower()
            if mode not in {"backfill", "rolling"}:
                mode = "backfill"

            today = datetime.now(timezone.utc).date()

            def process_case(case_obj: Dict[str, Any], search_meta: Dict[str, Any]) -> None:
                nonlocal api_calls_total, per_track_api_calls
                nonlocal per_track_cases_upserted, per_track_pdf_ok, per_track_pdf_empty, per_track_pdf_err
                nonlocal last_error

                if api_calls_total >= int(args.max_parser_api_calls):
                    return

                case_id = str(case_obj.get("CaseId") or "").strip()
                if not case_id:
                    return

                rec45 = upsert_case_to_catalog_45(
                    s,
                    domain,
                    headers,
                    catalog_45=cat_45,
                    fields_45=fields_45,
                    inn=inn_digits,
                    case=case_obj,
                    source=source,
                    search_meta=search_meta,
                    dry_run=bool(args.dry_run),
                )
                per_track_cases_upserted += 1
                out_summary["casesUpserted"] += 1

                rid45 = str(rec45.get("id") or rec45.get("recordId") or "").strip()
                vals45 = as_dict(rec45.get("values"))

                pdf_url = str(get_value(vals45, fields_45["pdf_url"]) or "").strip()
                pdf_text = str(get_value(vals45, fields_45["pdf_text"]) or "").strip()

                if not pdf_url and api_calls_total < int(args.max_parser_api_calls):
                    try:
                        api_calls_total += 1
                        per_track_api_calls += 1
                        out_summary["apiCalls"] += 1
                        out_summary["detailsCalls"] += 1

                        details = parser_api_details_by_id(s, api_key, case_id)
                        details_json_str = json.dumps(details, ensure_ascii=False)
                        extracted = extract_pdf_url_from_details_json_bfs(details)

                        patch: Dict[str, Any] = {
                            fields_45["details_fetched_at"]: iso_utc_now(),
                            fields_45["details_json"]: details_json_str,
                        }
                        if extracted and not pdf_url:
                            patch[fields_45["pdf_url"]] = extracted
                            pdf_url = extracted

                        if not args.dry_run and rid45:
                            bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch)
                    except Exception as exc:
                        last_error = redact_sensitive(f"details_by_id failed for CaseId={case_id}: {exc}")

                if pdf_url and not pdf_text and api_calls_total < int(args.max_parser_api_calls):
                    try:
                        api_calls_total += 1
                        per_track_api_calls += 1
                        out_summary["apiCalls"] += 1
                        out_summary["pdfCalls"] += 1

                        b64 = parser_api_pdf_download(s, api_key, pdf_url)
                        if not b64:
                            status, payload = "empty", ""
                        else:
                            status, payload = extract_text_from_pdf_base64(b64)
                    except Exception as exc:
                        status, payload = "error", str(exc)
                        payload = redact_sensitive(payload)

                    now = iso_utc_now()
                    if status == "ok":
                        per_track_pdf_ok += 1
                        out_summary["pdfOk"] += 1
                    elif status == "empty":
                        per_track_pdf_empty += 1
                        out_summary["pdfEmpty"] += 1
                    else:
                        per_track_pdf_err += 1
                        out_summary["pdfErr"] += 1
                        last_error = redact_sensitive(payload)

                    patch2: Dict[str, Any] = {
                        fields_45["pdf_text_status"]: status,
                        fields_45["pdf_text_fetched_at"]: now,
                        fields_45["pdf_text_error"]: payload if status == "error" else "",
                        fields_45["pdf_text"]: payload if status == "ok" else "",
                    }
                    if not args.dry_run and rid45:
                        bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch2)

            backfill_done = False

            if mode == "backfill":
                page = int(as_dict(cursor.get("backfill")).get("page") or 1)
                page = max(1, page)
                while True:
                    if api_calls_total >= int(args.max_parser_api_calls):
                        break
                    if per_track_cases_upserted >= int(args.max_cases_per_track):
                        break

                    try:
                        api_calls_total += 1
                        per_track_api_calls += 1
                        out_summary["apiCalls"] += 1

                        search = parser_api_search(
                            s,
                            api_key,
                            inn=inn_digits,
                            page=page,
                            date_from=date_from_backfill,
                            date_to="",
                        )
                    except Exception as exc:
                        last_error = redact_sensitive(f"search(backfill) failed: {exc}")
                        break

                    cases = as_list(search.get("Cases"))
                    pages_count = int(search.get("PagesCount") or 0)
                    if not cases:
                        backfill_done = True
                        cursor["mode"] = "rolling"
                        break

                    meta = {"mode": "backfill", "page": page, "dateFrom": date_from_backfill, "pagesCount": pages_count}
                    for c in cases:
                        if api_calls_total >= int(args.max_parser_api_calls):
                            break
                        if per_track_cases_upserted >= int(args.max_cases_per_track):
                            break
                        if isinstance(c, dict):
                            process_case(c, meta)

                    if api_calls_total >= int(args.max_parser_api_calls) or per_track_cases_upserted >= int(args.max_cases_per_track):
                        break

                    page += 1
                    cursor["backfill"]["page"] = page
                    if pages_count and page > pages_count:
                        backfill_done = True
                        cursor["mode"] = "rolling"
                        break

                if not backfill_done:
                    cursor["mode"] = "backfill"
                    cursor["backfill"]["page"] = int(cursor["backfill"].get("page") or page)

            else:
                df_rolling = date_minus_months(today, rolling_months).isoformat()
                if date_from_backfill and df_rolling < date_from_backfill:
                    df_rolling = date_from_backfill
                dt_rolling = today.isoformat()
                for page in range(1, max(1, rolling_max_pages) + 1):
                    if api_calls_total >= int(args.max_parser_api_calls):
                        break
                    if per_track_cases_upserted >= int(args.max_cases_per_track):
                        break
                    try:
                        api_calls_total += 1
                        per_track_api_calls += 1
                        out_summary["apiCalls"] += 1

                        search = parser_api_search(
                            s,
                            api_key,
                            inn=inn_digits,
                            page=page,
                            date_from=df_rolling,
                            date_to=dt_rolling,
                        )
                    except Exception as exc:
                        last_error = redact_sensitive(f"search(rolling) failed: {exc}")
                        break
                    cases = as_list(search.get("Cases"))
                    pages_count = int(search.get("PagesCount") or 0)
                    if not cases:
                        break
                    meta = {
                        "mode": "rolling",
                        "page": page,
                        "dateFrom": df_rolling,
                        "dateTo": dt_rolling,
                        "pagesCount": pages_count,
                    }
                    for c in cases:
                        if api_calls_total >= int(args.max_parser_api_calls):
                            break
                        if per_track_cases_upserted >= int(args.max_cases_per_track):
                            break
                        if isinstance(c, dict):
                            process_case(c, meta)

                cursor["mode"] = "rolling"
                cursor["rolling"]["months"] = rolling_months
                cursor["rolling"]["maxPages"] = rolling_max_pages

            cursor["last"] = {
                "apiCalls": per_track_api_calls,
                "casesUpserted": per_track_cases_upserted,
                "pdfOk": per_track_pdf_ok,
                "pdfEmpty": per_track_pdf_empty,
                "pdfErr": per_track_pdf_err,
                "updatedAt": iso_utc_now(),
            }
            if last_error:
                cursor["last"]["error"] = redact_sensitive(last_error)

            status = (
                f"{cursor.get('mode')} api={per_track_api_calls} cases={per_track_cases_upserted} "
                f"pdfOk={per_track_pdf_ok} pdfEmpty={per_track_pdf_empty} pdfErr={per_track_pdf_err}"
            )
            if str(cursor.get("mode")) == "backfill":
                status += f" page={int(as_dict(cursor.get('backfill')).get('page') or 1)}"

            if not args.dry_run and trid:
                bpium_patch_record_values(
                    s,
                    domain,
                    headers,
                    cat_44,
                    trid,
                    {
                        f44_last_sync_at: iso_utc_now(),
                        f44_last_req_at: iso_utc_now(),
                        f44_last_req_count: str(per_track_api_calls),
                        f44_last_req_log: cursor_to_json(cursor),
                        f44_last_sync_status: status,
                        f44_last_sync_error: redact_sensitive(last_error),
                    },
                )

            if args.debug:
                out_summary.setdefault("tracksDetails", []).append(
                    {
                        "trackRecordId": trid,
                        "inn": inn_digits,
                        "mode": cursor.get("mode"),
                        "cursor": cursor,
                        "status": status,
                        "lastError": last_error,
                    }
                )

        out_summary["tracks"]["processed"] = tracks_processed
        out_summary["apiCalls"] = api_calls_total

    print(json.dumps(out_summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
