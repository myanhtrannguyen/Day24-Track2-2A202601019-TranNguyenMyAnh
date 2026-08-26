"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]*\.md$", re.IGNORECASE)
_AGENT_ID = "governed-support-agent"
_RUN_TTL_SECONDS = 300


def _args_hash(args: dict) -> str:
    """Record a stable fingerprint, never raw tool arguments or PII."""
    canonical = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Accept only ticket numbers from filenames, not identifiers in document text."""
    ids: set[int] = set()
    for document in docs:
        match = _TICKET_FILE_RE.fullmatch(str(document.get("id", "")))
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customer_ids_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Map typed ticket IDs through the trusted relationship field only."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    requested = set(ticket_ids)
    return sorted(
        str(customer["customer_id"])
        for customer in customers
        if requested.intersection(customer.get("related_tickets", []))
    )


def _audit_decision(
    *,
    path: Path,
    run_id: str,
    tool: str,
    args: dict,
    context: policy.PolicyContext,
) -> bool:
    """Policy Enforcement Point used immediately before every real tool call."""
    allowed, reason = policy.check(context)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": _AGENT_ID,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": context.data_classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "agent_owner": context.agent_owner,
            "delegation_depth": context.delegation_depth,
            "egress_enabled": context.egress_enabled,
            "ttl_seconds": _RUN_TTL_SECONDS,
        },
        path,
    )
    return allowed


def _safe_summary_docs(docs: list[dict]) -> list[dict]:
    """Keep untrusted free text and PII out of the summarizer's context.

    Redaction is executed at the ingestion boundary.  The LLM receives only
    typed document metadata, so it cannot follow an instruction embedded in a
    ticket even if that instruction evades a string-based detector.
    """
    safe_docs: list[dict] = []
    for document in docs:
        # Execute the PII gate before any document could be passed to a model.
        source_text = str(document.get("text", ""))
        redacted_text = pii.redact(source_text)
        redaction_count = len(pii.detect(source_text))
        safe_docs.append(
            {
                "id": str(document.get("id", "unknown")),
                "text": (
                    "Untrusted ticket body withheld after PII sanitization; "
                    f"{redaction_count} entity(s) redacted from {len(redacted_text)} characters."
                ),
            }
        )
    return safe_docs


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Contain the lethal trifecta with separate untrusted and private runs."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex}"

    # Run A owns untrusted search only.  It never receives private records or
    # egress capability.
    search_context = policy.PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{run_id}:run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    docs: list[dict] = []
    if _audit_decision(
        path=ledger_path,
        run_id=run_id,
        tool="search_docs",
        args={"query": message},
        context=search_context,
    ):
        docs = tools.search_docs(message)

    # Detection creates audit evidence only.  Its customer IDs / URL are never
    # inputs to Run B or to http_post.
    # Evaluate the untrusted bundle only inside Run A.  This preserves evidence
    # for split-document lures while still preventing its parsed values from
    # becoming inputs to the private-data run.
    combined_untrusted_text = "\n\n".join(str(doc.get("text", "")) for doc in docs)
    observed_injection = llm.find_injection(combined_untrusted_text) is not None
    ticket_ids = _ticket_ids(docs)

    # Run B receives a typed allow-listed relationship, derived from filenames
    # and customers.json.  Attacker-written document text cannot name a record
    # for this run to read.
    customer_ids = _customer_ids_for_tickets(ticket_ids)
    read_context = policy.PolicyContext(
        data_classification="restricted",
        request_purpose="ticket-reconciliation",
        agent_owner=f"{run_id}:run-b",
        delegation_depth=1,
        egress_enabled=False,
    )
    for customer_id in customer_ids:
        if _audit_decision(
            path=ledger_path,
            run_id=run_id,
            tool="read_customer",
            args={"customer_id": customer_id},
            context=read_context,
        ):
            # Private records remain in Run B and are not returned to Run A,
            # the LLM, a tool argument, or the final response.
            tools.read_customer(customer_id)

    if observed_injection:
        # Treat untrusted egress intent as a request to the PEP, then stop at
        # the gate.  The target and customer parsed from free text are not
        # propagated; this gives a deny evidence record without a network call.
        egress_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="untrusted-instruction-review",
            agent_owner=f"{run_id}:run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        _audit_decision(
            path=ledger_path,
            run_id=run_id,
            tool="http_post",
            args={"request": "blocked-untrusted-egress"},
            context=egress_context,
        )

    return llm.summarize(_safe_summary_docs(docs))
