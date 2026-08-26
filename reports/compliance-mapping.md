# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade trong phạm vi lab; không tuyên bố control chưa có. Private store duy nhất và dữ liệu ledger được tách riêng để đây là hạng mục stretch có thể thực hiện được. | `data/customers.json`; `Guide.md:140` (stretch #3) |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory phân biệt `--mock` (không gửi API) và `--model`; model chỉ nhận metadata đã qua PII gate, còn egress restricted bị PEP từ chối. | `reports/dpia-lite.md:28-49`; `agent/runner.py:130-152`; `agent/policy.py:46-51` |
| ASI03 — privilege abuse | Per-run UUID, owner theo Run A/B, delegation depth và TTL 300 giây được ghi cho từng decision; private run không có egress enabled. | `agent/runner.py:100-127`; `agent/runner.py:155-220`; `reports/ledger.jsonl` |
| ASI01 — goal hijack | Trifecta split chỉ chuyển ticket ID từ filename sang Run B, rồi map qua `related_tickets`; customer ID/URL trong text injection không được truyền đi. | `agent/runner.py:79-97`; `agent/runner.py:179-230`; `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | Policy-as-code trả reason cho mọi allow/deny; ledger hash-chain kiểm tra evidence audit và phát hiện tamper. | `agent/policy.py:39-59`; `agent/ledger.py:44-99`; `tests/test_policy.py`; `tests/test_ledger.py` |
