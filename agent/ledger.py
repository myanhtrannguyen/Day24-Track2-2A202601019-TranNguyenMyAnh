"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


_GENESIS_HASH = "0" * 64


def _canonical_hash(entry: dict) -> str:
    """Hash the canonical JSON representation excluding its stored hash."""
    payload = {key: value for key, value in entry.items() if key != "hash"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return _GENESIS_HASH
    try:
        last_line = path.read_text(encoding="utf-8").splitlines()[-1]
        return str(json.loads(last_line)["hash"])
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot append to a malformed audit ledger") from exc


def append(entry: dict, path: Path) -> dict:
    """Append an immutable hash-chained audit record to JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = dict(entry)
    record.pop("hash", None)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _canonical_hash(record)
    with path.open("a", encoding="utf-8") as ledger_file:
        ledger_file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def verify(path: Path) -> bool:
    """Verify completeness and the full hash chain, returning False on tamper."""
    if not path.exists():
        return True

    expected_previous = _GENESIS_HASH
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                return False
            record = json.loads(line)
            if not isinstance(record, dict):
                return False
            if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                return False
            if not isinstance(record.get("decision"), str) or not record["decision"].strip():
                return False
            if record.get("prev_hash") != expected_previous:
                return False
            stored_hash = record.get("hash")
            if not isinstance(stored_hash, str) or stored_hash != _canonical_hash(record):
                return False
            expected_previous = stored_hash
    except (OSError, TypeError, json.JSONDecodeError):
        return False
    return True
