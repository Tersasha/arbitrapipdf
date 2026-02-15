# Bpium KAD Pipeline (GitHub Actions)

This repo runs workers in GitHub Actions to sync арбитражные дела (KAD) into Bpium and extract PDF text:
1. scan tracking records in Bpium catalog 44 (INN + SearchFromDate),
2. search cases via parser-api (`/search`) and upsert them into Bpium catalog 45,
3. fetch case details (`/details_by_id`) to get `PdfUrl` + store `DetailsJson`,
4. download PDF via parser-api (`/pdf_download`) as base64,
5. extract `PdfText` using `pypdf`,
6. (optional) enrich catalog 45 with flattened MVP fields from `DetailsJson` (no parser-api calls for backfill).

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

## 2) Workflows
### 2.1 Main pipeline (44 -> 45 + PdfText)
GitHub -> `Actions` -> `Bpium KAD Pipeline (44 -> 45 PdfText)` -> `Run workflow`

Inputs:
- `track_record_id` (optional) - process exactly one tracking record from catalog 44
- `max_tracks_per_run` (default: 1) - keep small to protect parser-api token budget
- `max_parser_api_calls` (default: 15) - budget per run
- `max_cases_per_track` (default: 50)
- `rolling_max_pages` (default: 3)
- `dry_run` (default: false)
- `debug` (default: false)

### 2.2 Enrich backfill (catalog 45 from existing DetailsJson, no parser-api calls)
GitHub -> `Actions` -> `Bpium KAD Enrich Backfill (catalog 45 from DetailsJson)` -> `Run workflow`

This workflow reads existing records in catalog 45 and fills new MVP fields from `DetailsJson` **without** spending parser-api calls.

### 2.3 (Deprecated) PdfText backfill
Workflow `(Deprecated) Bpium PdfText Backfill (manual)` is kept as a manual tool.

## 3) Catalog 45 schema patch (append-only)
To add MVP enrichment fields into Bpium catalog 45 without deleting existing fields:

```bash
python bpium_patch_catalog_fields.py --domain https://<tenant>.bpium.ru --catalog-id 45 --preset results45_enrich_mvp
```

This script is **append-only**: it first `GET`s catalog fields, appends missing new ones, and then `PATCH`es the full fields array.

## 4) Notes
- PDF text extraction is done in GitHub Actions with `pypdf` (Bpium does not need PDFBox/Java).
- Keep this repo public only if you never commit any secrets.

## 5) Automatic mode
`Bpium KAD Pipeline` has a daily schedule and processes a conservative batch each run.
