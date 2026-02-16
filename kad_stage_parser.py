import re
from typing import Any, Dict, List, Literal, Set


Stage = Literal["FIRST", "APPEAL", "CASSATION", "OTHER"]
Lifecycle = Literal["ACTIVE", "FINISHED", "UNKNOWN"]


RE_HAS_INSTANCE = re.compile(r"инстанц", re.IGNORECASE | re.UNICODE)
RE_FIRST_WORD = re.compile(r"перв(ая|ой|ую|ые|ых|ым|ыми)", re.IGNORECASE | re.UNICODE)
RE_FIRST_NUM = re.compile(r"(^|[^0-9a-zа-я])(1|i)\s*[-]?\s*я([^0-9a-zа-я]|$)", re.IGNORECASE | re.UNICODE)
RE_APPEAL = re.compile(r"апелляц|апелляцион|апелл", re.IGNORECASE | re.UNICODE)
RE_CASSATION = re.compile(r"кассац|кассацион", re.IGNORECASE | re.UNICODE)
RE_FINISHED = re.compile(
    r"рассмотрение дела завершено|дела завершено|дело завершено",
    re.IGNORECASE | re.UNICODE,
)
RE_OTHER_HINT = re.compile(
    r"надзор|верховн|вс рф|пересмотр|нов(ым|ыми) обстоятельств|вновь открывш",
    re.IGNORECASE | re.UNICODE,
)

RE_INST_FIRST = re.compile(r"первая", re.IGNORECASE | re.UNICODE)
RE_INST_APPEAL = re.compile(r"апелляцион|апелляц", re.IGNORECASE | re.UNICODE)
RE_INST_CASSATION = re.compile(r"кассацион|кассац", re.IGNORECASE | re.UNICODE)
RE_INST_OTHER = re.compile(r"надзор|верховн|пересмотр", re.IGNORECASE | re.UNICODE)

STAGE_ORDER: Dict[Stage, int] = {"FIRST": 1, "APPEAL": 2, "CASSATION": 3, "OTHER": 0}


def normalize_ru(value: Any) -> str:
    s = str(value or "")
    s = s.strip().lower()
    s = s.replace("ё", "е")
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", " ", s)
    return s


def parse_case_state(raw_state: Any) -> Dict[str, Any]:
    normalized = normalize_ru(raw_state)
    raw = "" if raw_state is None else str(raw_state)

    if not normalized:
        return {
            "lifecycle": "UNKNOWN",
            "activeStages": [],
            "raw": raw,
            "normalized": normalized,
        }

    if RE_FINISHED.search(normalized):
        return {
            "lifecycle": "FINISHED",
            "activeStages": [],
            "raw": raw,
            "normalized": normalized,
        }

    looks_like_instance_state = RE_HAS_INSTANCE.search(normalized) is not None
    stages: Set[Stage] = set()

    if RE_APPEAL.search(normalized):
        stages.add("APPEAL")
    if RE_CASSATION.search(normalized):
        stages.add("CASSATION")
    if RE_FIRST_WORD.search(normalized) or RE_FIRST_NUM.search(f" {normalized} "):
        stages.add("FIRST")

    if not stages:
        if (not looks_like_instance_state) or RE_OTHER_HINT.search(normalized):
            stages.add("OTHER")
        else:
            stages.add("OTHER")

    ordered = sorted(stages, key=lambda s: STAGE_ORDER.get(s, 0), reverse=True)
    return {
        "lifecycle": "ACTIVE",
        "activeStages": ordered,
        "raw": raw,
        "normalized": normalized,
    }


def parse_instance_name(raw_name: Any) -> Dict[str, Any]:
    normalized = normalize_ru(raw_name)
    raw = "" if raw_name is None else str(raw_name)

    if not normalized:
        return {"stage": "OTHER", "raw": raw, "normalized": normalized, "confidence": "LOW"}
    if RE_INST_APPEAL.search(normalized):
        return {"stage": "APPEAL", "raw": raw, "normalized": normalized, "confidence": "HIGH"}
    if RE_INST_CASSATION.search(normalized):
        return {"stage": "CASSATION", "raw": raw, "normalized": normalized, "confidence": "HIGH"}
    if RE_INST_FIRST.search(normalized):
        return {"stage": "FIRST", "raw": raw, "normalized": normalized, "confidence": "HIGH"}
    if RE_INST_OTHER.search(normalized):
        return {"stage": "OTHER", "raw": raw, "normalized": normalized, "confidence": "HIGH"}
    return {"stage": "OTHER", "raw": raw, "normalized": normalized, "confidence": "LOW"}


def render_case_stage_for_field(parsed_case_state: Dict[str, Any]) -> str:
    lifecycle = str(parsed_case_state.get("lifecycle") or "")
    active = parsed_case_state.get("activeStages") or []

    if lifecycle == "FINISHED":
        return "FINISHED"
    if lifecycle != "ACTIVE":
        return "OTHER"
    if not active:
        return "OTHER"

    uniq: List[str] = []
    for s in active:
        ss = str(s).upper().strip()
        if ss and ss not in uniq:
            uniq.append(ss)
    return ",".join(uniq) if uniq else "OTHER"

