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

from kad_stage_parser import parse_case_state, parse_instance_name, render_case_stage_for_field


PARSER_API_BASE = "https://parser-api.com/parser/arbitr_api"


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_secrets(text: str) -> str:
    s = str(text or "")
    # Redact parser-api key query param
    s = re.sub(r"([?&]key=)[^&#\\s]+", r"\\1<redacted>", s, flags=re.IGNORECASE)
    # Redact auth header if it ever appears
    s = re.sub(r"(Authorization\\s*:\\s*)([^\\r\\n]+)", r"\\1<redacted>", s, flags=re.IGNORECASE)
    return s


def safe_url(url: str) -> str:
    return redact_secrets(url)


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


def needs_short_localization_fix(v: Any) -> bool:
    s = str(v or "").strip().lower()
    if not s:
        return False
    return "plus " in s or "; +" in s


def should_patch_mvp_field(name: str, old_value: Any, new_value: Any, *, force: bool = False) -> bool:
    if force:
        return True
    if not has_value(new_value):
        return False
    if not has_value(old_value):
        return True

    if name == "Finished":
        old_bool = is_truthy(old_value)
        new_bool = is_truthy(new_value)
        if old_bool and not new_bool:
            return False
        return old_bool != new_bool

    if name in {"State", "Finished"}:
        return str(old_value).strip() != str(new_value).strip()
    if name in {"PlaintiffsShort", "RespondentsShort"}:
        return needs_short_localization_fix(old_value)
    return False


def build_mvp_patch(existing_values: Dict[str, Any], mvp_ids: Dict[str, str], mvp: Dict[str, Any], *, force: bool = False) -> Dict[str, Any]:
    patch: Dict[str, Any] = {}
    for name, value in mvp.items():
        fid = mvp_ids.get(name)
        if not fid:
            continue
        old_value = get_value(existing_values, fid)
        if should_patch_mvp_field(name, old_value, value, force=force):
            patch[fid] = value
    return patch


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


def parse_iso_dt(s: Any) -> Optional[datetime]:
    ss = str(s or "").strip()
    if not ss:
        return None
    try:
        if ss.endswith("Z"):
            return datetime.fromisoformat(ss.replace("Z", "+00:00"))
        return datetime.fromisoformat(ss)
    except Exception:
        return None


def dt_to_utc_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def select_case_root(details: Any) -> Dict[str, Any]:
    root = as_dict(details)
    cases = as_list(root.get("Cases"))
    if cases and isinstance(cases[0], dict):
        return as_dict(cases[0])
    return root


def short_list_by_name(items: List[Dict[str, Any]]) -> str:
    names = [str(it.get("Name") or "").strip() for it in items if isinstance(it, dict) and str(it.get("Name") or "").strip()]
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return f"{names[0]}; \u0435\u0449\u0451 {len(names) - 1}"


def join_names(items: List[Dict[str, Any]]) -> str:
    out: List[str] = []
    for it in items:
        nm = str(it.get("Name") or "").strip()
        if nm:
            out.append(nm)
    return "; ".join(out)


def _event_dt(ev: Dict[str, Any]) -> Optional[datetime]:
    for key in ("PublishDate", "Date"):
        d = parse_iso_dt(ev.get(key))
        if d is not None:
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d
    return None


def _instance_num(inst: Dict[str, Any]) -> int:
    try:
        return int(inst.get("InstanceNumber") or 0)
    except Exception:
        return 0


def _instance_stage(inst: Dict[str, Any]) -> str:
    parsed = parse_instance_name(inst.get("Name"))
    return str(parsed.get("stage") or "OTHER")


def _instance_has_judges(inst: Dict[str, Any]) -> bool:
    judges = [x for x in as_list(inst.get("Judges")) if isinstance(x, dict) and str(x.get("Name") or "").strip()]
    return len(judges) > 0


def _instance_is_finished(inst: Dict[str, Any]) -> bool:
    file_obj = as_dict(inst.get("File"))
    if str(file_obj.get("URL") or "").strip():
        return True
    for ev in as_list(inst.get("InstanceEvents")):
        if not isinstance(ev, dict):
            continue
        finish_raw = ev.get("FinishEvent")
        if finish_raw is True:
            return True
        if str(finish_raw).strip() in {"1", "true", "True"}:
            return True
    return False


def _instance_best_dt(inst: Dict[str, Any], *, finished_only: bool = False) -> Optional[datetime]:
    best: Optional[datetime] = None
    for ev in as_list(inst.get("InstanceEvents")):
        if not isinstance(ev, dict):
            continue
        if finished_only:
            finish_raw = ev.get("FinishEvent")
            is_final = finish_raw is True or str(finish_raw).strip() in {"1", "true", "True"}
            if not is_final:
                continue
        d = _event_dt(ev)
        if d is None:
            continue
        if best is None or d > best:
            best = d
    if best is not None:
        return best
    if finished_only:
        file_obj = as_dict(inst.get("File"))
        d = _event_dt(file_obj)
        if d is not None:
            return d
    return None


def _choose_instance_for_case(case: Dict[str, Any], active_stages: List[str], lifecycle: str) -> Optional[Dict[str, Any]]:
    instances = [x for x in as_list(case.get("CaseInstances")) if isinstance(x, dict)]
    if not instances:
        return None

    if lifecycle == "FINISHED":
        best_inst: Optional[Dict[str, Any]] = None
        best_dt: Optional[datetime] = None
        for inst in instances:
            d = _instance_best_dt(inst, finished_only=True)
            if d is None:
                continue
            if best_dt is None or d > best_dt:
                best_dt = d
                best_inst = inst
        if best_inst is not None:
            return best_inst

    stage_priority = {"CASSATION": 3, "APPEAL": 2, "FIRST": 1, "OTHER": 0}
    target_stage = "OTHER"
    if active_stages:
        target_stage = sorted(
            [str(s).upper() for s in active_stages],
            key=lambda s: stage_priority.get(s, 0),
            reverse=True,
        )[0]

    same_stage = [inst for inst in instances if _instance_stage(inst) == target_stage]
    candidates = same_stage if same_stage else instances

    def key_fn(inst: Dict[str, Any]) -> Tuple[int, int, int, int]:
        not_finished = 1 if not _instance_is_finished(inst) else 0
        has_judges = 1 if _instance_has_judges(inst) else 0
        d = _instance_best_dt(inst, finished_only=False)
        ts = int(d.timestamp()) if d else 0
        return (not_finished, has_judges, ts, _instance_num(inst))

    chosen = sorted(candidates, key=key_fn, reverse=True)[0]
    return chosen


def _extract_finished(case: Dict[str, Any], state_field_value: str) -> bool:
    if state_field_value == "FINISHED":
        return True

    case_finished_raw = case.get("Finished")
    if case_finished_raw is True or str(case_finished_raw).strip() in {"1", "true", "True"}:
        return True

    instances = [x for x in as_list(case.get("CaseInstances")) if isinstance(x, dict)]
    for inst in instances:
        file_obj = as_dict(inst.get("File"))
        if str(file_obj.get("URL") or "").strip():
            return True
        for ev in as_list(inst.get("InstanceEvents")):
            if not isinstance(ev, dict):
                continue
            finish_raw = ev.get("FinishEvent")
            if finish_raw is True or str(finish_raw).strip() in {"1", "true", "True"}:
                return True
    return False


def extract_mvp_from_details(details: Dict[str, Any]) -> Dict[str, Any]:
    case = select_case_root(details)

    plaintiffs = [x for x in as_list(case.get("Plaintiffs")) if isinstance(x, dict)]
    respondents = [x for x in as_list(case.get("Respondents")) if isinstance(x, dict)]
    thirds = [x for x in as_list(case.get("Thirds")) if isinstance(x, dict)]

    state_raw = str(case.get("State") or "").strip()
    parsed_state = parse_case_state(state_raw)
    active_stages = [str(s).upper() for s in parsed_state.get("activeStages") or []]
    lifecycle = str(parsed_state.get("lifecycle") or "UNKNOWN")
    state_field_value = render_case_stage_for_field(parsed_state)

    instances = [x for x in as_list(case.get("CaseInstances")) if isinstance(x, dict)]
    cur_inst = _choose_instance_for_case(case, active_stages, lifecycle)

    court = as_dict(cur_inst.get("Court")) if isinstance(cur_inst, dict) else {}
    judges = [x for x in as_list(cur_inst.get("Judges")) if isinstance(x, dict)] if isinstance(cur_inst, dict) else []
    if not judges:
        for inst in instances:
            cand = [x for x in as_list(inst.get("Judges")) if isinstance(x, dict)]
            if cand:
                judges = cand
                break

    now = datetime.now(timezone.utc)
    hearings = [x for x in as_list(case.get("CourtHearings")) if isinstance(x, dict)]
    future: List[Tuple[datetime, Dict[str, Any]]] = []
    for h in hearings:
        d = parse_iso_dt(h.get("Start"))
        if d is None:
            continue
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        if d >= now:
            future.append((d, h))
    future.sort(key=lambda t: t[0])
    next_h = future[0][1] if future else None

    events: List[Dict[str, Any]] = []
    for inst in instances:
        for ev in as_list(inst.get("InstanceEvents")):
            if isinstance(ev, dict):
                events.append(ev)

    max_sum = 0.0
    for ev in events:
        try:
            v = float(ev.get("ClaimSum") or 0)
        except Exception:
            v = 0.0
        if v > max_sum:
            max_sum = v

    last_ev: Optional[Dict[str, Any]] = None
    last_ev_dt: Optional[datetime] = None
    for ev in events:
        d = _event_dt(ev)
        if d is None:
            continue
        if last_ev_dt is None or d > last_ev_dt:
            last_ev_dt = d
            last_ev = ev

    docs = [ev for ev in events if isinstance(ev.get("File"), str) and str(ev.get("File") or "").strip().lower().startswith("http")]
    signed = [ev for ev in events if ev.get("HasSignature") is True]

    last_ev_with_url: Optional[Dict[str, Any]] = None
    last_ev_url_dt: Optional[datetime] = None
    for ev in events:
        file_url = str(ev.get("File") or "").strip()
        if not file_url.lower().startswith("http"):
            continue
        d = _event_dt(ev)
        if d is None:
            continue
        if last_ev_url_dt is None or d > last_ev_url_dt:
            last_ev_url_dt = d
            last_ev_with_url = ev

    out: Dict[str, Any] = {
        "ClaimSumValue": max_sum if max_sum > 0 else None,
        "ClaimCurrency": "RUB" if max_sum > 0 else "",
        "PlaintiffsShort": short_list_by_name(plaintiffs),
        "RespondentsShort": short_list_by_name(respondents),
        "PlaintiffsCount": len(plaintiffs),
        "RespondentsCount": len(respondents),
        "ThirdsCount": len(thirds),
        "CurrentInstance": active_stages[0] if active_stages else (_instance_stage(cur_inst) if isinstance(cur_inst, dict) else "OTHER"),
        "State": state_field_value,
        "Finished": _extract_finished(case, state_field_value),
        "CourtCode": str(court.get("Code") or "").strip(),
        "CourtName": str(court.get("Name") or "").strip(),
        "Judges": join_names(judges),
        "NextHearingAt": dt_to_utc_z(parse_iso_dt(next_h.get("Start"))) if isinstance(next_h, dict) and parse_iso_dt(next_h.get("Start")) else "",
        "NextHearingLocation": str(next_h.get("Location") or "").strip() if isinstance(next_h, dict) else "",
        "LastEventAt": dt_to_utc_z(last_ev_dt) if last_ev_dt is not None else "",
        "LastEventSummary": (
            f"{str(last_ev.get('EventTypeName') or '').strip()} / {str(last_ev.get('EventContentTypeName') or '').strip()}"
            if isinstance(last_ev, dict)
            else ""
        ).strip(" /"),
        "LastEventUrl": (
            str(last_ev_with_url.get("File") or "").strip()
            if isinstance(last_ev_with_url, dict) and isinstance(last_ev_with_url.get("File"), str)
            else ""
        ),
        "DocsCount": len(docs),
        "SignedDocsCount": len(signed),
        "HasSignedDocs": True if len(signed) > 0 else False,
    }
    if out.get("ClaimSumValue") is None:
        out.pop("ClaimSumValue", None)
    return out

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
            resp = exc.response
            if resp is not None:
                try:
                    snippet = (resp.text or "").replace("\r", " ").replace("\n", " ")[:800]
                except Exception:
                    snippet = "<unavailable>"
                raise RuntimeError(
                    f"HTTP {resp.status_code} for {safe_url(getattr(resp, 'url', url))}; body={redact_secrets(snippet)!r}"
                ) from exc
            raise
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(backoff[attempt] if attempt < len(backoff) else 2**attempt)
                continue
            raise RuntimeError(redact_secrets(str(exc))) from exc
    if last_exc:
        raise RuntimeError(redact_secrets(str(last_exc))) from last_exc
    raise RuntimeError("request failed without exception")


def bpium_get_catalog_fields_map(
    session: requests.Session, base_url: str, headers: Dict[str, str], catalog_id: str
) -> Dict[str, str]:
    data = request_json(session, "GET", f"{base_url}/api/v1/catalogs/{catalog_id}", headers=headers, timeout=60)
    if not isinstance(data, dict):
        return {}
    out: Dict[str, str] = {}
    for f in data.get("fields") or []:
        if isinstance(f, dict) and f.get("id") is not None:
            out[str(f.get("name", "")).strip()] = str(f.get("id"))
    return out


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
        "enrichOk": 0,
        "enrichSkip": 0,
        "enrichErr": 0,
        "dryRun": bool(args.dry_run),
        "updatedAt": iso_utc_now(),
    }

    with requests.Session() as s:
        # Resolve enriched field ids by name. If fields are not added yet, enrichment is skipped silently.
        cat45_name_to_id = bpium_get_catalog_fields_map(s, domain, headers, cat_45)
        mvp_field_names = [
            "State",
            "Finished",
            "ClaimSumValue",
            "ClaimCurrency",
            "PlaintiffsShort",
            "RespondentsShort",
            "PlaintiffsCount",
            "RespondentsCount",
            "ThirdsCount",
            "CurrentInstance",
            "CourtCode",
            "CourtName",
            "Judges",
            "NextHearingAt",
            "NextHearingLocation",
            "LastEventAt",
            "LastEventSummary",
            "LastEventUrl",
            "DocsCount",
            "SignedDocsCount",
            "HasSignedDocs",
            "EnrichAt",
            "EnrichStatus",
            "EnrichError",
        ]
        mvp_ids: Dict[str, str] = {n: cat45_name_to_id[n] for n in mvp_field_names if n in cat45_name_to_id}

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
                pdf_status_existing = str(get_value(vals45, fields_45["pdf_text_status"]) or "").strip().lower()
                details_json_existing = str(get_value(vals45, fields_45["details_json"]) or "").strip()

                # If we already have DetailsJson, try enriching MVP fields without extra parser-api calls.
                if mvp_ids and details_json_existing and rid45:
                    try:
                        parsed = json.loads(details_json_existing)
                        mvp = extract_mvp_from_details(parsed if isinstance(parsed, dict) else {})
                        patch_mvp = build_mvp_patch(vals45, mvp_ids, mvp, force=False)

                        if patch_mvp:
                            fid_at = mvp_ids.get("EnrichAt")
                            fid_status = mvp_ids.get("EnrichStatus")
                            fid_err = mvp_ids.get("EnrichError")
                            if fid_at:
                                patch_mvp[fid_at] = iso_utc_now()
                            if fid_status:
                                patch_mvp[fid_status] = "ok"
                            if fid_err:
                                patch_mvp[fid_err] = ""

                            if not args.dry_run:
                                bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch_mvp)
                            out_summary["enrichOk"] += 1
                        else:
                            out_summary["enrichSkip"] += 1
                    except Exception as exc:
                        out_summary["enrichErr"] += 1
                        last_error = f"enrich(from detailsJson) failed for CaseId={case_id}: {redact_secrets(str(exc))}"
                        fid_status = mvp_ids.get("EnrichStatus")
                        fid_err = mvp_ids.get("EnrichError")
                        fid_at = mvp_ids.get("EnrichAt")
                        if fid_status and fid_err and not args.dry_run:
                            patch_err: Dict[str, Any] = {fid_status: "error", fid_err: redact_secrets(str(exc))[:2000]}
                            if fid_at:
                                patch_err[fid_at] = iso_utc_now()
                            bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch_err)

                # Fetch details if we do not have DetailsJson yet, or if PdfUrl is missing.
                if (not details_json_existing or not pdf_url) and api_calls_total < int(args.max_parser_api_calls):
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

                        # Enrich MVP fields from details (Git-side parsing; Bpium stores flat fields).
                        if mvp_ids:
                            try:
                                mvp = extract_mvp_from_details(details if isinstance(details, dict) else {})
                                patch_mvp = build_mvp_patch(vals45, mvp_ids, mvp, force=False)

                                if patch_mvp:
                                    fid_at = mvp_ids.get("EnrichAt")
                                    fid_status = mvp_ids.get("EnrichStatus")
                                    fid_err = mvp_ids.get("EnrichError")
                                    if fid_at:
                                        patch_mvp[fid_at] = iso_utc_now()
                                    if fid_status:
                                        patch_mvp[fid_status] = "ok"
                                    if fid_err:
                                        patch_mvp[fid_err] = ""
                                    if not args.dry_run and rid45:
                                        bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch_mvp)
                                    out_summary["enrichOk"] += 1
                                else:
                                    out_summary["enrichSkip"] += 1
                            except Exception as exc:
                                out_summary["enrichErr"] += 1
                                last_error = f"enrich failed for CaseId={case_id}: {redact_secrets(str(exc))}"
                                fid_status = mvp_ids.get("EnrichStatus")
                                fid_err = mvp_ids.get("EnrichError")
                                fid_at = mvp_ids.get("EnrichAt")
                                if fid_status and fid_err and not args.dry_run and rid45:
                                    patch_err: Dict[str, Any] = {fid_status: "error", fid_err: redact_secrets(str(exc))[:2000]}
                                    if fid_at:
                                        patch_err[fid_at] = iso_utc_now()
                                    bpium_patch_record_values(s, domain, headers, cat_45, rid45, patch_err)
                    except Exception as exc:
                        last_error = f"details_by_id failed for CaseId={case_id}: {exc}"

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
                        last_error = payload

                    patch2: Dict[str, Any] = {
                        fields_45["pdf_text_fetched_at"]: now,
                        fields_45["pdf_text_error"]: payload if status == "error" else "",
                    }
                    if status == "ok" and payload:
                        patch2[fields_45["pdf_text_status"]] = "ok"
                        patch2[fields_45["pdf_text"]] = payload
                    else:
                        # Never erase a previously successful PdfText on transient errors/empty responses.
                        if not pdf_text:
                            patch2[fields_45["pdf_text_status"]] = status
                        elif pdf_status_existing != "ok":
                            patch2[fields_45["pdf_text_status"]] = status
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
                        last_error = f"search(backfill) failed: {exc}"
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
                        last_error = f"search(rolling) failed: {exc}"
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
                cursor["last"]["error"] = last_error

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
                        f44_last_sync_error: last_error,
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
