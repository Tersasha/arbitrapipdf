import argparse
import base64
import json
import os
import sys
from typing import Any, Dict, List

import requests


def build_auth_header(login: str, password: str) -> str:
    token = f"{login}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def request_json(session: requests.Session, method: str, url: str, *, headers: Dict[str, str], json_body: Any = None) -> Any:
    resp = session.request(method, url, headers=headers, json=json_body, timeout=60)
    resp.raise_for_status()
    return resp.json()


def get_catalog(session: requests.Session, base_url: str, headers: Dict[str, str], catalog_id: str) -> Dict[str, Any]:
    data = request_json(session, "GET", f"{base_url}/api/v1/catalogs/{catalog_id}", headers=headers)
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected catalog response: {type(data)}")
    return data


def patch_catalog_append_fields(
    session: requests.Session, base_url: str, headers: Dict[str, str], catalog_id: str, new_fields: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    IMPORTANT: Bpium PATCH /api/v1/catalogs/{id} expects the FULL `fields` array.
    If you send only new fields, Bpium will delete the old ones.

    This function is append-only:
    1) GET catalog -> existing fields
    2) payload.fields = existing + missing(new)
    3) PATCH catalog
    4) GET catalog again (stable output)
    """
    before = get_catalog(session, base_url, headers, catalog_id)
    existing = before.get("fields") or []
    if not isinstance(existing, list):
        raise RuntimeError("Catalog.fields is not a list")

    existing_names = {str(f.get("name", "")).strip() for f in existing if isinstance(f, dict)}
    to_add = [f for f in new_fields if str(f.get("name", "")).strip() not in existing_names]

    payload = {"fields": existing + to_add}
    request_json(session, "PATCH", f"{base_url}/api/v1/catalogs/{catalog_id}", headers=headers, json_body=payload)
    return get_catalog(session, base_url, headers, catalog_id)


def mk_field(name: str, ftype: str, config: Dict[str, Any]) -> Dict[str, Any]:
    # Matches shape returned by GET /api/v1/catalogs/{id} for existing fields, but without id/prevId.
    # For new fields, Bpium assigns ids.
    return {
        "duplicateResultWithPrevId": False,
        "name": name,
        "required": False,
        "type": ftype,
        "hint": "",
        "isSystem": False,
        "history": True,
        "filterable": True,
        "apiOnly": False,
        "hidden": False,
        "comment": "",
        "config": config,
        "visible": {},
        "formulaConfig": {},
        "formulaType": None,
    }


def preset_results45_enrich_mvp() -> List[Dict[str, Any]]:
    num_cfg = {"unit": "", "type": "number", "min": "", "max": ""}
    date_dt_cfg = {"type": "date", "time": True, "defaultValue": False}
    text_cfg = {"type": "text", "mask": None}
    ml_cfg = {"type": "multiline", "mask": None}
    sw_cfg = {"value": False, "type": "switch"}

    return [
        mk_field("ClaimSumValue", "number", num_cfg),
        mk_field("ClaimCurrency", "text", text_cfg),
        mk_field("PlaintiffsShort", "text", text_cfg),
        mk_field("RespondentsShort", "text", text_cfg),
        mk_field("PlaintiffsCount", "number", num_cfg),
        mk_field("RespondentsCount", "number", num_cfg),
        mk_field("ThirdsCount", "number", num_cfg),
        mk_field("CurrentInstance", "text", text_cfg),
        mk_field("CourtCode", "text", text_cfg),
        mk_field("CourtName", "text", text_cfg),
        mk_field("Judges", "text", text_cfg),
        mk_field("NextHearingAt", "date", date_dt_cfg),
        mk_field("NextHearingLocation", "text", text_cfg),
        mk_field("LastEventAt", "date", date_dt_cfg),
        mk_field("LastEventSummary", "text", ml_cfg),
        mk_field("LastEventUrl", "text", text_cfg),
        mk_field("DocsCount", "number", num_cfg),
        mk_field("SignedDocsCount", "number", num_cfg),
        mk_field("HasSignedDocs", "switch", sw_cfg),
        mk_field("EnrichAt", "date", date_dt_cfg),
        mk_field("EnrichStatus", "text", text_cfg),
        mk_field("EnrichError", "text", ml_cfg),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True, help="https://<tenant>.bpium.ru")
    ap.add_argument("--catalog-id", required=True, help="Bpium catalog id (e.g. 45)")
    ap.add_argument("--preset", choices=["results45_enrich_mvp"], required=True)
    args = ap.parse_args()

    login = os.getenv("BPIUM_LOGIN")
    password = os.getenv("BPIUM_PASSWORD")
    if not login or not password:
        print("BPIUM_LOGIN/BPIUM_PASSWORD must be set.", file=sys.stderr)
        return 2

    base_url = args.domain.rstrip("/")
    headers = {
        "Authorization": build_auth_header(login, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if args.preset == "results45_enrich_mvp":
        new_fields = preset_results45_enrich_mvp()
    else:
        raise RuntimeError("unsupported preset")

    with requests.Session() as s:
        updated = patch_catalog_append_fields(s, base_url, headers, str(args.catalog_id), new_fields)

    # Print mapping name -> id so workers can resolve field ids by name if needed.
    out: Dict[str, Any] = {}
    for f in updated.get("fields") or []:
        if isinstance(f, dict):
            out[str(f.get("name", "")).strip()] = f.get("id")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

