# Bpium PdfText Worker (GitHub Actions)

This repo runs a small worker in GitHub Actions to:
1. read a single Bpium record,
2. download a PDF via parser-api (`/pdf_download`) as base64,
3. extract text from PDF,
4. write text to a Bpium field (`PdfText`) and store status/error.

No local server is required.

## 1) GitHub Secrets
In your GitHub repository:
`Settings -> Secrets and variables -> Actions -> New repository secret`

Add:
- `BPIUM_DOMAIN` (e.g. `https://company.bpium.ru`)
- `BPIUM_LOGIN`
- `BPIUM_PASSWORD`
- `PARSER_API_KEY`

Optional (only if your field IDs differ from defaults):
- `BPIUM_CATALOG_ID` (default: `45`)
- `BPIUM_FIELD_PDF_URL` (default: `7`)
- `BPIUM_FIELD_PDF_TEXT` (default: `19`)
- `BPIUM_FIELD_PDF_TEXT_FETCHED_AT` (default: `20`)
- `BPIUM_FIELD_PDF_TEXT_STATUS` (default: `21`)
- `BPIUM_FIELD_PDF_TEXT_ERROR` (default: `22`)

## 2) Run
GitHub -> `Actions` -> `Bpium PdfText Backfill` -> `Run workflow`

Inputs:
- `record_id` (optional) - if empty, the worker scans the catalog and fills records with empty `PdfText`
- `budget` (default: 10) - max parser-api calls (keep small to protect tokens)
- `page_size` (default: 100) - Bpium page size for scanning
- `max_scan` (default: 2000) - max records to scan per run
- `retry_errors` (default: true) - retry records with `PdfTextStatus=error` (with cooldown)
- `cooldown_hours` (default: 24) - skip recently-attempted records unless `force=true`
- `force` (default: false) - write even if `PdfText` already exists
- `dry_run` (default: false) - do not write back to Bpium

## 3) Notes
- The worker does NOT depend on Java/PDFBox in Bpium. It extracts text with `pypdf`.
- It is safe to keep this repo public if you never commit secrets into the code.

## 4) Automatic mode
The workflow has an hourly schedule (`cron`) and will process a small batch each run (default budget: 10).
