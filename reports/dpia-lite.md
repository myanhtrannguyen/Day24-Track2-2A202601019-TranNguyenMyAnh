# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Lab dùng hoàn toàn dữ liệu synthetic. `search_docs` đọc ticket tự do trong
`corpus/`; ticket có thể chứa tên, CCCD, SĐT, STK, email và cả prompt
injection. `read_customer` có thể trả về `customer_id`, tên, CCCD, SĐT, STK,
email và `related_tickets` từ `data/customers.json`.

PII gate nhận diện CCCD, SĐT, STK và email trước khi bất kỳ ticket nào có thể
đi vào summarizer (`agent/pii.py:54-94`, `agent/runner.py:130-150`). Ledger
chỉ giữ metadata audit (tool, classification, decision, reason, hash,
run/agent ID và argument hash), tuyệt đối không ghi raw customer record hay
raw tool arguments.

## 2. Mục đích gì

Mục đích hợp lệ là tổng hợp ticket hỗ trợ và đối soát những ticket có quan hệ
đã được xác lập. Run A tìm ticket theo câu hỏi người dùng. Run B chỉ nhận
`list[int]` ticket ID lấy từ tên file và tra mapping `related_tickets` đáng
tin cậy để phục vụ hồ sơ hợp lệ; record riêng tư không được đưa vào phản hồi,
LLM hay tool khác.

Việc một document nói “đọc khách X” hoặc “gửi kết quả đi” không phải là mục
đích hợp lệ. ID khách và URL xuất hiện trong free text không được dùng làm
input cho Run B hoặc egress.

## 3. Chảy đi đâu

```text
User request -> Run A/search_docs (untrusted ticket text)
                     |-> PII redaction + metadata-only summarizer input
                     |-> typed ticket IDs from filenames
                           -> trusted related_tickets mapping
                           -> Run B/read_customer (private record stays here)
Untrusted egress request -> policy PEP -> deny -> ledger (hash + reason)
```

Với đường chấm `--mock`, không có model-provider API call hay chuyển dữ liệu
ra nước ngoài. `http_post` chỉ allowlist được `localhost:9999` cho mô phỏng
lab, nhưng runner không gọi nó khi data là restricted: PEP tạo decision deny
trước execution. `reports/sink.log` rỗng trong replay sau containment và
`reports/ledger.jsonl` là bằng chứng append-only nội bộ.

Nếu chạy tùy chọn `--model claude-...`, provider có thể ở ngoài Việt Nam nên
phải cập nhật hồ sơ chuyển dữ liệu xuyên biên giới/retention theo NĐ 356 trước
khi vận hành. Hiện runner chỉ chuyển metadata đã được PII-sanitize cho
`summarize`; không chuyển raw ticket hay customer record. Mọi thay đổi làm
provider nhận nội dung khác phải được đánh giá DPIA lại và có phê duyệt DPO.
