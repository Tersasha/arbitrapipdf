import argparse
import base64
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

from bpium_http import request_json


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_auth_header(login: str, password: str) -> str:
    token = f"{login}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def as_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def get_value(values: Dict[str, Any], field_id: str) -> Any:
    if field_id in values:
        return values[field_id]
    try:
        i = int(field_id)
    except Exception:
        return None
    return values.get(i)


def digits_only(s: str) -> str:
    return re.sub(r"\D+", "", str(s or ""))


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
    fields_json: str = "",
) -> List[Dict[str, Any]]:
    params: Dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
        "sortField": "id",
        "sortType": "-1",
    }
    if fields_json:
        params["fields"] = fields_json
    data = request_json(
        session,
        "GET",
        f"{base_url}/api/v1/catalogs/{catalog_id}/records",
        headers=headers,
        params=params,
        timeout=60,
    )
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
    return request_json(
        session,
        "PATCH",
        f"{base_url}/api/v1/catalogs/{catalog_id}/records/{record_id}",
        headers=headers,
        json_body={"values": values},
        timeout=60,
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Backfill CounterpartyName in catalog 45 from catalog 44 by INN"
    )
    ap.add_argument("--catalog-44", default=os.getenv("BPIUM_TRACKING_CATALOG_ID") or "44")
    ap.add_argument("--catalog-45", default=os.getenv("BPIUM_RESULTS_CATALOG_ID") or "45")
    ap.add_argument("--page-size-44", type=int, default=200)
    ap.add_argument("--page-size-45", type=int, default=200)
    ap.add_argument("--max-scan-44", type=int, default=20000)
    ap.add_argument("--max-scan-45", type=int, default=20000)
    ap.add_argument("--max-updates", type=int, default=2000)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true", help="Overwrite non-empty values in catalog 45")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    domain = os.getenv("BPIUM_DOMAIN", "").rstrip("/")
    login = os.getenv("BPIUM_LOGIN", "")
    password = os.getenv("BPIUM_PASSWORD", "")
    if not domain or not login or not password:
        print("Missing env vars: BPIUM_DOMAIN, BPIUM_LOGIN, BPIUM_PASSWORD")
        return 2

    headers = {
        "Authorization": build_auth_header(login, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    scanned44 = 0
    scanned45 = 0
    updated = 0
    skipped = 0
    errors = 0
    skip_reasons: Dict[str, int] = {}

    with requests.Session() as s:
        map44 = bpium_get_catalog_fields_map(s, domain, headers, str(args.catalog_44))
        map45 = bpium_get_catalog_fields_map(s, domain, headers, str(args.catalog_45))

        f44_inn = os.getenv("BPIUM_44_INN") or "14"
        f45_inn = os.getenv("BPIUM_45_INN") or "2"
        f44_counterparty = os.getenv("BPIUM_44_COUNTERPARTY_NAME") or ""
        f45_counterparty = os.getenv("BPIUM_45_COUNTERPARTY_NAME") or ""

        if not f44_counterparty:
            for n in ("CounterpartyName", "Название контрагента"):
                if n in map44:
                    f44_counterparty = map44[n]
                    break
        if not f45_counterparty:
            for n in ("CounterpartyName", "Название контрагента"):
                if n in map45:
                    f45_counterparty = map45[n]
                    break

        if not f44_counterparty or not f45_counterparty:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "CounterpartyName field id not resolved. Set BPIUM_44_COUNTERPARTY_NAME and BPIUM_45_COUNTERPARTY_NAME.",
                    },
                    ensure_ascii=False,
                )
            )
            return 3

        # 1) Build INN -> counterparty mapping from catalog 44.
        inn_to_name: Dict[str, str] = {}
        offset = 0
        while scanned44 < int(args.max_scan_44):
            page = bpium_list_records(
                s,
                domain,
                headers,
                str(args.catalog_44),
                limit=int(args.page_size_44),
                offset=offset,
                fields_json=json.dumps([f44_inn, f44_counterparty]),
            )
            if not page:
                break
            for rec in page:
                if scanned44 >= int(args.max_scan_44):
                    break
                scanned44 += 1
                vals = as_dict(rec.get("values"))
                inn = digits_only(str(get_value(vals, f44_inn) or ""))
                name = str(get_value(vals, f44_counterparty) or "").strip()
                if len(inn) not in (10, 12) or not name:
                    continue
                prev = inn_to_name.get(inn, "")
                if not prev or len(name) > len(prev):
                    inn_to_name[inn] = name
            offset += int(args.page_size_44)

        # 2) Backfill catalog 45.
        offset = 0
        while scanned45 < int(args.max_scan_45) and updated < int(args.max_updates):
            page = bpium_list_records(
                s,
                domain,
                headers,
                str(args.catalog_45),
                limit=int(args.page_size_45),
                offset=offset,
                fields_json=json.dumps([f45_inn, f45_counterparty]),
            )
            if not page:
                break

            for rec in page:
                if scanned45 >= int(args.max_scan_45) or updated >= int(args.max_updates):
                    break
                scanned45 += 1
                rid = str(rec.get("id") or rec.get("recordId") or "").strip()
                vals = as_dict(rec.get("values"))

                inn = digits_only(str(get_value(vals, f45_inn) or ""))
                cur = str(get_value(vals, f45_counterparty) or "").strip()
                if len(inn) not in (10, 12):
                    skipped += 1
                    skip_reasons["no_valid_inn"] = skip_reasons.get("no_valid_inn", 0) + 1
                    continue

                target = inn_to_name.get(inn, "").strip()
                if not target:
                    skipped += 1
                    skip_reasons["no_match_in_44"] = skip_reasons.get("no_match_in_44", 0) + 1
                    continue

                if not args.force and cur:
                    skipped += 1
                    skip_reasons["already_has_value"] = skip_reasons.get("already_has_value", 0) + 1
                    continue
                if cur == target:
                    skipped += 1
                    skip_reasons["already_same"] = skip_reasons.get("already_same", 0) + 1
                    continue

                try:
                    if not args.dry_run:
                        bpium_patch_record_values(
                            s,
                            domain,
                            headers,
                            str(args.catalog_45),
                            rid,
                            {str(f45_counterparty): target},
                        )
                    updated += 1
                    if args.debug:
                        print(
                            json.dumps(
                                {"recordId": rid, "inn": inn, "counterparty": target, "status": "updated"},
                                ensure_ascii=False,
                            )
                        )
                except Exception as exc:
                    errors += 1
                    if args.debug:
                        print(
                            json.dumps(
                                {
                                    "recordId": rid,
                                    "inn": inn,
                                    "status": "error",
                                    "error": str(exc),
                                },
                                ensure_ascii=False,
                            )
                        )
            offset += int(args.page_size_45)

    summary = {
        "ok": True,
        "mode": "counterparty_backfill",
        "catalog44": str(args.catalog_44),
        "catalog45": str(args.catalog_45),
        "mapInns": len(inn_to_name),
        "scanned44": scanned44,
        "scanned45": scanned45,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "dryRun": bool(args.dry_run),
        "skipReasons": skip_reasons,
        "updatedAt": iso_utc_now(),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

