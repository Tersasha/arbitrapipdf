import re
from typing import Any, Dict, List


Stage = str  # FIRST | APPEAL | CASSATION | OTHER


def normalize_ru(s: Any) -> str:
    str_v = ("" if s is None else str(s))
    return (
        str_v.strip()
        .lower()
        .replace("ё", "е")
        .replace("–", "-")
        .replace("—", "-")
        .replace("\u00a0", " ")
        .replace("\t", " ")
    )


def _collapse_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s)


RE_HAS_INSTANCE = re.compile(r"инстанц", re.IGNORECASE)
RE_FIRST_WORD = re.compile(r"перв(ая|ой|ую|ые|ых|ым|ыми)", re.IGNORECASE)
RE_FIRST_NUM = re.compile(r"(^|[^0-9a-zа-я])(1|i)\s*[-]?\s*я([^0-9a-zа-я]|$)", re.IGNORECASE)
RE_APPEAL = re.compile(r"апелляц|апелляцион|апелл", re.IGNORECASE)
RE_CASSATION = re.compile(r"кассац|кассацион", re.IGNORECASE)
RE_FINISHED = re.compile(r"рассмотрение дела завершено|дела завершено|дело завершено", re.IGNORECASE)
RE_OTHER_HINT = re.compile(r"надзор|верховн|вс рф|пересмотр|нов(ым|ыми) обстоятельств|вновь открывш", re.IGNORECASE)

RE_INST_FIRST = re.compile(r"первая", re.IGNORECASE)
RE_INST_APPEAL = re.compile(r"апелляцион|апелляц", re.IGNORECASE)
RE_INST_CASSATION = re.compile(r"кассацион|кассац", re.IGNORECASE)
RE_INST_OTHER = re.compile(r"надзор|верховн|пересмотр", re.IGNORECASE)


def _ordered(stages_set: set) -> List[Stage]:
    order = ["FIRST", "APPEAL", "CASSATION", "OTHER"]
    return [s for s in order if s in stages_set]


def parse_case_state(raw_state: Any) -> Dict[str, Any]:
    normalized = _collapse_spaces(normalize_ru(raw_state))
    raw = "" if raw_state is None else str(raw_state)
    if not normalized:
        return {"lifecycle": "UNKNOWN", "activeStages": [], "raw": raw, "normalized": normalized}

    if RE_FINISHED.search(normalized):
        return {"lifecycle": "FINISHED", "activeStages": [], "raw": raw, "normalized": normalized}

    looks_like_instance = bool(RE_HAS_INSTANCE.search(normalized))
    stages = set()

    if RE_APPEAL.search(normalized):
        stages.add("APPEAL")
    if RE_CASSATION.search(normalized):
        stages.add("CASSATION")
    if RE_FIRST_WORD.search(normalized) or RE_FIRST_NUM.search(f" {normalized} "):
        stages.add("FIRST")

    if not stages:
        # Even if we cannot parse a concrete stage, keep explicit OTHER for diagnostics/polling logic.
        if (not looks_like_instance) or RE_OTHER_HINT.search(normalized):
            stages.add("OTHER")
        else:
            stages.add("OTHER")

    return {"lifecycle": "ACTIVE", "activeStages": _ordered(stages), "raw": raw, "normalized": normalized}


def parse_instance_name(raw_name: Any) -> Dict[str, Any]:
    normalized = _collapse_spaces(normalize_ru(raw_name))
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


def render_case_stage_for_field(raw_state: Any) -> str:
    """
    Compact representation for Bpium text field:
      FINISHED | UNKNOWN | FIRST | APPEAL | CASSATION | FIRST,APPEAL ...
    """
    parsed = parse_case_state(raw_state)
    lc = parsed.get("lifecycle")
    if lc == "FINISHED":
        return "FINISHED"
    if lc == "UNKNOWN":
        return "UNKNOWN"
    stages = parsed.get("activeStages") or []
    if not stages:
        return "UNKNOWN"
    return ",".join(stages)

