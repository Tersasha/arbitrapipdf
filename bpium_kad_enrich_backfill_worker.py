import argparse
import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from bpium_http import redact_sensitive, request_json
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


def is_meaningful_value(v: Any) -> bool:
    """
    Decide whether we should WRITE the extracted value into Bpium.

    We must not patch "empty" values into typed fields (e.g. date), because Bpium can reject them
    with validation errors ("Invalid Date"). Also we avoid overwriting already-filled fields.
    """
    if v is None:
        return False
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return True
    return bool(str(v).strip())


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
    fields_json: str = "",
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/v1/catalogs/{catalog_id}/records"
    params: Dict[str, str] = {"limit": str(limit), "offset": str(offset), "sortField": sort_field, "sortType": sort_type}
    if fields_json:
        params["fields"] = str(fields_json)
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
    return f"{names[0]}; plus {len(names) - 1}"


def extract_mvp(details: Dict[str, Any]) -> Dict[str, Any]:
    case = select_case_root(details)
    case_state_raw = case.get("State")
    case_state = parse_case_state(case_state_raw)
    active_stages = set(case_state.get("activeStages") or [])

    plaintiffs = [x for x in as_list(case.get("Plaintiffs")) if isinstance(x, dict)]
    respondents = [x for x in as_list(case.get("Respondents")) if isinstance(x, dict)]
    thirds = [x for x in as_list(case.get("Thirds")) if isinstance(x, dict)]

    instances = [x for x in as_list(case.get("CaseInstances")) if isinstance(x, dict)]
    cur_inst = None
    if instances:

        def inst_num(x: Dict[str, Any]) -> int:
            try:
                return int(x.get("InstanceNumber") or 0)
            except Exception:
                return 0

        def inst_finished(x: Dict[str, Any]) -> bool:
            fv = x.get("FinishEvent")
            if isinstance(fv, dict):
                return len(fv) > 0
            return bool(fv)

        active_instances = [ins for ins in instances if not inst_finished(ins)] or list(instances)
        if active_stages and "OTHER" not in active_stages:
            matched = [ins for ins in active_instances if parse_instance_name(ins.get("Name")).get("stage") in active_stages]
            if matched:
                active_instances = matched
        with_judges = [ins for ins in active_instances if any(isinstance(j, dict) for j in as_list(ins.get("Judges")))]
        candidates = with_judges or active_instances
        cur_inst = sorted(candidates, key=inst_num)[-1]

    court = as_dict(cur_inst.get("Court")) if isinstance(cur_inst, dict) else {}
    judges = [x for x in as_list(cur_inst.get("Judges")) if isinstance(x, dict)] if isinstance(cur_inst, dict) else []
    if not judges:
        for ins in instances:
            j = [x for x in as_list(ins.get("Judges")) if isinstance(x, dict)]
            if j:
                judges = j
                break

    current_instance_stage = parse_instance_name(cur_inst.get("Name")).get("stage") if isinstance(cur_inst, dict) else "OTHER"
    if current_instance_stage == "OTHER" and case_state.get("lifecycle") == "ACTIVE" and len(active_stages) == 1:
        current_instance_stage = list(active_stages)[0]

    now = datetime.now(timezone.utc)
    hearings = [x for x in as_list(case.get("CourtHearings")) if isinstance(x, dict)]
    future: List[Tuple[datetime, Dict[str, Any]]] = []
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

    def ev_dt(ev: Dict[str, Any]) -> Optional[datetime]:
        for k in ("PublishDate", "Date"):
            d = parse_dt(ev.get(k))
            if d is not None:
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                return d
        return None

    last_ev = None
    last_ev_dt = None
    last_ev_with_file = None
    last_ev_with_file_dt = None
    for ev in events:
        d = ev_dt(ev)
        if d is None:
            continue
        if last_ev_dt is None or d > last_ev_dt:
            last_ev_dt = d
            last_ev = ev
        if isinstance(ev.get("File"), str) and str(ev.get("File") or "").strip().lower().startswith("http"):
            if last_ev_with_file_dt is None or d > last_ev_with_file_dt:
                last_ev_with_file_dt = d
                last_ev_with_file = ev

    docs = [ev for ev in events if isinstance(ev.get("File"), str) and str(ev.get("File") or "").strip().lower().startswith("http")]
    signed = [ev for ev in events if ev.get("HasSignature") is True]

    out: Dict[str, Any] = {
        "ClaimSumValue": max_sum if max_sum > 0 else None,
        "ClaimCurrency": "RUB" if max_sum > 0 else "",
        "PlaintiffsShort": short_list(plaintiffs),
        "RespondentsShort": short_list(respondents),
        "PlaintiffsCount": len(plaintiffs),
        "RespondentsCount": len(respondents),
        "ThirdsCount": len(thirds),
        "CurrentInstance": str(current_instance_stage or ""),
        "State": render_case_stage_for_field(case_state_raw),
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
        "LastEventUrl": (
            str(last_ev_with_file.get("File") or "").strip()
            if isinstance(last_ev_with_file, dict) and isinstance(last_ev_with_file.get("File"), str)
            else ""
        ),
        "DocsCount": len(docs),
        "SignedDocsCount": len(signed),
        "HasSignedDocs": True if len(signed) > 0 else False,
    }
    if out.get("ClaimSumValue") is None:
        out.pop("ClaimSumValue", None)
    return out


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

        fid_details_json = name_to_id.get("DetailsJson")
        if not fid_details_json:
            print(json.dumps({"ok": False, "error": "DetailsJson field not found in catalog", "catalogId": args.catalog_id}))
            return 3

        mvp_names = [
            "ClaimSumValue",
            "ClaimCurrency",
            "PlaintiffsShort",
            "RespondentsShort",
            "PlaintiffsCount",
            "RespondentsCount",
            "ThirdsCount",
            "CurrentInstance",
            "State",
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

                need = args.force
                if not need:
                    for name, fid in mvp_ids.items():
                        if not fid or name in {"EnrichAt", "EnrichStatus", "EnrichError"}:
                            continue
                        if not has_value(get_value(vals, str(fid))):
                            need = True
                            break
                if not need:
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
                        print(json.dumps({"recordId": rid, "status": "error", "error": redact_sensitive(str(exc))}, ensure_ascii=False))
                    if mvp_ids.get("EnrichStatus") and mvp_ids.get("EnrichError") and not args.dry_run and rid:
                        patch_err: Dict[str, Any] = {
                            str(mvp_ids["EnrichStatus"]): "error",
                            str(mvp_ids["EnrichError"]): redact_sensitive(str(exc))[:2000],
                        }
                        if mvp_ids.get("EnrichAt"):
                            patch_err[str(mvp_ids["EnrichAt"])] = iso_utc_now()
                        bpium_patch_record_values(s, domain, headers, str(args.catalog_id), rid, patch_err)
                    continue

                patch: Dict[str, Any] = {}
                for name, value in mvp.items():
                    fid = mvp_ids.get(name)
                    if not fid:
                        continue
                    if not is_meaningful_value(value):
                        continue
                    if args.force or not has_value(get_value(vals, str(fid))):
                        patch[str(fid)] = value

                # enrich meta
                if mvp_ids.get("EnrichAt") and (args.force or not has_value(get_value(vals, str(mvp_ids["EnrichAt"])))):
                    patch[str(mvp_ids["EnrichAt"])] = iso_utc_now()
                if mvp_ids.get("EnrichStatus") and (args.force or not has_value(get_value(vals, str(mvp_ids["EnrichStatus"])))):
                    patch[str(mvp_ids["EnrichStatus"])] = "ok" if patch else "skip"
                if mvp_ids.get("EnrichError") and (args.force or not has_value(get_value(vals, str(mvp_ids["EnrichError"])))):
                    patch[str(mvp_ids["EnrichError"])] = ""

                if not patch:
                    skipped += 1
                    continue

                processed += 1
                if not args.dry_run and rid:
                    try:
                        bpium_patch_record_values(s, domain, headers, str(args.catalog_id), rid, patch)
                        updated += 1
                    except Exception as exc:
                        errors += 1
                        if args.debug:
                            print(
                                json.dumps(
                                    {"recordId": rid, "status": "error", "error": redact_sensitive(str(exc))},
                                    ensure_ascii=False,
                                )
                            )
                        continue
                else:
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
