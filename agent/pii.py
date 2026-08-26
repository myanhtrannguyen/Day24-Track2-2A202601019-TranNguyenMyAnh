"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


# Các recognizer được viết theo thứ tự ưu tiên.  Một dãy 12 số sau ``STK``
# là số tài khoản, không phải CCCD, nên phải được nhận diện trước CCCD.
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])")
_BANK_ACCOUNT_RE = re.compile(
    r"(?i)\b(?:stk|số\s*tài\s*khoản|tai\s*khoan)\b\s*(?:là|la|:|-)?\s*"
    r"(?P<value>\d{8,16})(?!\d)"
)
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(?:0\d{9}|\+84[\s.-]?\d{9})(?!\d)")


def _append_non_overlapping(entities: list[dict], entity: dict) -> None:
    """Append an entity unless a more-specific earlier recognizer owns it."""
    if any(entity["start"] < old["end"] and old["start"] < entity["end"] for old in entities):
        return
    entities.append(entity)


def detect(text: str) -> list[dict]:
    """Return offsets for the Vietnamese PII formats handled by this lab.

    The detector intentionally uses deterministic, inspectable regexes.  It
    avoids sending customer text to a third-party NER service before the PII
    gate has had an opportunity to redact it.
    """
    entities: list[dict] = []

    for match in _EMAIL_RE.finditer(text):
        _append_non_overlapping(
            entities, {"type": "EMAIL", "start": match.start(), "end": match.end()}
        )
    for match in _BANK_ACCOUNT_RE.finditer(text):
        _append_non_overlapping(
            entities,
            {
                "type": "VN_BANK_ACCOUNT",
                "start": match.start("value"),
                "end": match.end("value"),
            },
        )
    for match in _CCCD_RE.finditer(text):
        _append_non_overlapping(
            entities, {"type": "VN_CCCD", "start": match.start(), "end": match.end()}
        )
    for match in _PHONE_RE.finditer(text):
        _append_non_overlapping(
            entities, {"type": "VN_PHONE", "start": match.start(), "end": match.end()}
        )

    return sorted(entities, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    """Replace every detected entity without invalidating later offsets."""
    result = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        placeholder = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + placeholder + result[entity["end"] :]
    return result
