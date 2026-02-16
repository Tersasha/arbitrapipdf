import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

from kad_stage_parser import parse_case_state, parse_instance_name, render_case_stage_for_field


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


def redact_secrets(text: str) -> str:
    s = str(text or "")
    # Redact parser-api key query param
    s = re.sub(r"([?&]key=)[^&#\\s]+", r"\\1<redacted>", s, flags=re.IGNORECASE)
    # Redact basic/bearer auth if it ever appears
    s = re.sub(r"(Authorization\\s*:\\s*)([^\\r\\n]+)", r"\\1<redacted>", s, flags=re.IGNORECASE)
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
    backoff: Iterable[int] = (1, 2),
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
                    snippet = (resp.text or "").replace("\\r", " ").replace("\\n", " ")[:800]
                except Exception:
                    snippet = "<unavailable>"
                safe_url = redact_secrets(getattr(resp, "url", url))
                raise RuntimeError(f"HTTP {resp.status_code} for {safe_url}; body={redact_secrets(snippet)!r}") from exc
            raise
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                delay = list(backoff)[attempt] if attempt < len(list(backoff)) else 2**attempt
                time.sleep(delay)
                continue
            raise RuntimeError(redact_secrets(str(exc))) from exc
    if last_exc:
        raise RuntimeError(redact_secrets(str(last_exc))) from last_exc
    raise RuntimeError("request failed without exception")


def bpium_get_catalog_fields_map(session: requests.Session, base_url: str, headers: Dict[str, str], catalog_id: str) -> Dict[str, str]:
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
    sort_field: str = "id",
    sort_type: str = "-1",
    filters_json: str = "",
    fields_json: str = "",
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records"
    params: Dict[str, str] = {"limit": str(limit), "offset": str(offset), "sortField": sort_field, "sortType": sort_type}
    if filters_json:
        params["filters"] = filters_json
    if fields_json:
        params["fields"] = fields_json
    data = request_json(session, "GET", url, headers=headers, params=params, timeout=60)
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected records list type: {type(data)}")
    return [x for x in data if isinstance(x, dict)]


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


def select_case_root(details: Any) -> Dict[str, Any]:
    root = as_dict(details)
    cases = as_list(root.get("Cases"))
    if cases and isinstance(cases[0], dict):
        return as_dict(cases[0])
    return root


def parse_dt(s: Any) -> Optional[datetime]:
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


def join_names(items: List[Dict[str, Any]]) -> str:
    names: List[str] = []
    for it in items:
        nm = str(it.get("Name") or "").strip()
        if nm:
            names.append(nm)
    return "; ".join(names)


def short_list(items: List[Dict[str, Any]]) -> str:
    names = [str(it.get("Name") or "").strip() for it in items if isinstance(it, dict) and str(it.get("Name") or "").strip()]
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return f"{names[0]}; \u0435\u0449\u0451 {len(names) - 1}"


def _event_dt(ev: Dict[str, Any]) -> Optional[datetime]:
    for key in ("PublishDate", "Date"):
        d = parse_dt(ev.get(key))
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


def extract_mvp(details: Dict[str, Any]) -> Dict[str, Any]:
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
    future = []
    for h in hearings:
        d = parse_dt(h.get("Start"))
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

    last_ev = None
    last_ev_dt = None
    for ev in events:
        d = _event_dt(ev)
        if d is None:
            continue
        if last_ev_dt is None or d > last_ev_dt:
            last_ev_dt = d
            last_ev = ev

    docs = [ev for ev in events if isinstance(ev.get("File"), str) and str(ev.get("File") or "").strip().lower().startswith("http")]
    signed = [ev for ev in events if ev.get("HasSignature") is True]

    last_ev_with_url = None
    last_ev_url_dt = None
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
        "State": state_field_value,
        "Finished": _extract_finished(case, state_field_value),
        "ClaimSumValue": max_sum if max_sum > 0 else None,
        "ClaimCurrency": "RUB" if max_sum > 0 else "",
        "PlaintiffsShort": short_list(plaintiffs),
        "RespondentsShort": short_list(respondents),
        "PlaintiffsCount": len(plaintiffs),
        "RespondentsCount": len(respondents),
        "ThirdsCount": len(thirds),
        "CurrentInstance": active_stages[0] if active_stages else (_instance_stage(cur_inst) if isinstance(cur_inst, dict) else "OTHER"),
        "CourtCode": str(court.get("Code") or "").strip(),
        "CourtName": str(court.get("Name") or "").strip(),
        "Judges": join_names(judges),
        "NextHearingAt": dt_to_utc_z(parse_dt(next_h.get("Start"))) if isinstance(next_h, dict) and parse_dt(next_h.get("Start")) else "",
        "NextHearingLocation": str(next_h.get("Location") or "").strip() if isinstance(next_h, dict) else "",
        "LastEventAt": dt_to_utc_z(last_ev_dt) if last_ev_dt is not None else "",
        "LastEventSummary": (
            f"{str(last_ev.get('EventTypeName') or '').strip()} / {str(last_ev.get('EventContentTypeName') or '').strip()}"
            if isinstance(last_ev, dict)
            else ""
        ).strip(" /"),
        "LastEventUrl": str(last_ev_with_url.get("File") or "").strip() if isinstance(last_ev_with_url, dict) and isinstance(last_ev_with_url.get("File"), str) else "",
        "DocsCount": len(docs),
        "SignedDocsCount": len(signed),
        "HasSignedDocs": True if len(signed) > 0 else False,
    }
    if out.get("ClaimSumValue") is None:
        out.pop("ClaimSumValue", None)
    return out


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
        old_bool = str(old_value).strip().lower() in {"1", "true", "yes", "y", "on"}
        new_bool = str(new_value).strip().lower() in {"1", "true", "yes", "y", "on"}
        if old_bool and not new_bool:
            return False
        return old_bool != new_bool

    if name in {"State", "Finished"}:
        return str(old_value).strip() != str(new_value).strip()
    if name in {"PlaintiffsShort", "RespondentsShort"}:
        return needs_short_localization_fix(old_value)
    return False

def main() -> int:
    ap = argparse.ArgumentParser(description="Backfill enriched MVP fields in catalog 45 from DetailsJson")
    ap.add_argument("--catalog-id", default="45")
    ap.add_argument("--page-size", type=int, default=100)
    ap.add_argument("--max-records", type=int, default=200)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--force", action="store_true", help="Overwrite already filled fields")
    args = ap.parse_args()

    domain = os.getenv("BPIUM_DOMAIN", "").rstrip("/")
    login = os.getenv("BPIUM_LOGIN", "")
    password = os.getenv("BPIUM_PASSWORD", "")
    if not domain or not login or not password:
        print("Missing env vars: BPIUM_DOMAIN, BPIUM_LOGIN, BPIUM_PASSWORD", file=sys.stderr)
        return 2

    headers = {"Authorization": build_auth_header(login, password), "Accept": "application/json", "Content-Type": "application/json"}

    scanned = 0
    processed = 0
    updated = 0
    skipped = 0
    errors = 0

    with requests.Session() as s:
        name_to_id = bpium_get_catalog_fields_map(s, domain, headers, str(args.catalog_id))

        # Required fields
        fid_details_json = name_to_id.get("DetailsJson")
        if not fid_details_json:
            print(json.dumps({"ok": False, "error": "DetailsJson field not found in catalog", "catalogId": args.catalog_id}))
            return 3

        mvp_names = [
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
        mvp_ids = {n: name_to_id.get(n) for n in mvp_names if name_to_id.get(n)}

        offset = 0
        page_size = max(1, int(args.page_size))
        max_records = max(1, int(args.max_records))

        while scanned < max_records:
            fields_json = json.dumps([fid_details_json] + [v for v in mvp_ids.values()], ensure_ascii=False)
            page = bpium_list_records(
                s,
                domain,
                headers,
                str(args.catalog_id),
                limit=page_size,
                offset=offset,
                sort_field="id",
                sort_type="-1",
                fields_json=fields_json,
            )
            if not page:
                break

            for rec in page:
                if scanned >= max_records:
                    break
                scanned += 1

                rid = str(rec.get("id") or rec.get("recordId") or "").strip()
                vals = as_dict(rec.get("values"))

                raw_details = get_value(vals, fid_details_json)
                if not has_value(raw_details):
                    skipped += 1
                    continue

                try:
                    details = json.loads(str(raw_details))
                    if not isinstance(details, dict):
                        raise ValueError("DetailsJson is not an object")
                    mvp = extract_mvp(details)
                except Exception as exc:
                    errors += 1
                    if args.debug:
                        print(json.dumps({"recordId": rid, "status": "error", "error": redact_secrets(str(exc))}, ensure_ascii=False))
                    # store enrich error if fields exist
                    if mvp_ids.get("EnrichStatus") and mvp_ids.get("EnrichError") and not args.dry_run and rid:
                        bpium_patch_record_values(
                            s,
                            domain,
                            headers,
                            str(args.catalog_id),
                            rid,
                            {
                                str(mvp_ids["EnrichStatus"]): "error",
                                str(mvp_ids["EnrichError"]): redact_secrets(str(exc))[:2000],
                                str(mvp_ids.get("EnrichAt") or ""): iso_utc_now() if mvp_ids.get("EnrichAt") else "",
                            },
                        )
                    continue

                patch: Dict[str, Any] = {}
                for name, value in mvp.items():
                    fid = mvp_ids.get(name)
                    if not fid:
                        continue
                    old_value = get_value(vals, str(fid))
                    if should_patch_mvp_field(name, old_value, value, force=bool(args.force)):
                        patch[str(fid)] = value

                # enrich meta
                if mvp_ids.get("EnrichAt") and (patch or args.force):
                    patch[str(mvp_ids["EnrichAt"])] = iso_utc_now()
                if mvp_ids.get("EnrichStatus") and (patch or args.force):
                    patch[str(mvp_ids["EnrichStatus"])] = "ok"
                if mvp_ids.get("EnrichError") and (patch or args.force):
                    patch[str(mvp_ids["EnrichError"])] = ""

                if not patch:
                    skipped += 1
                    continue

                processed += 1
                if not args.dry_run and rid:
                    bpium_patch_record_values(s, domain, headers, str(args.catalog_id), rid, patch)
                updated += 1
                if args.debug:
                    print(json.dumps({"recordId": rid, "status": "updated", "keys": list(patch.keys())}, ensure_ascii=False))

            offset += page_size

    summary = {
        "ok": True,
        "mode": "enrich-backfill",
        "catalogId": str(args.catalog_id),
        "scanned": scanned,
        "processed": processed,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "dryRun": bool(args.dry_run),
        "updatedAt": iso_utc_now(),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
