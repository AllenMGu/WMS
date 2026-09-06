# Controlled evidence attachments & business reports (P0/P1) — overview (EN)

Full Chinese details: [CONTROLLED_EVIDENCE_AND_REPORTS.md](./CONTROLLED_EVIDENCE_AND_REPORTS.md).

## 1. Controlled file objects (`app/gsp/attachments/`)

- `POST /api/gsp/files` streams the upload, computes SHA-256 server-side and
  stores it immutably, content-addressed under `ATTACHMENT_DIR` (sha256[0:2]/sha256).
- File type is decided server-side from content (PDF/JPEG/PNG/WebP, OLE2
  `.doc`/`.xls` via olefile stream names, OOXML docx/xlsx via zipfile +
  Content_Types XML, ZIP, CSV/TXT); lying declared types are rejected (422).
- Business records bind through `gspf:<object_key>` tokens
  (`bindings.resolve_attachment`): the object must be ACTIVE with a matching
  purpose (or OTHER), and the persisted hash/size come from the server object.
  Bound records: partner qualification documents, supplier-product
  authorisations (single + bulk import), drug registration documents and
  carrier documents.
- `ATTACHMENT_POLICY`: **`enforce` is required in production** —
  `Settings.validate()` refuses startup with any other value when
  `APP_ENV=production`; `warn` is only for legacy-data migration.
- Downloads re-verify size + SHA-256 before returning bytes (tamper → 410).
- Disable is the only lifecycle change: quality managers may disable any file;
  an uploader may retire only their own file that no business record
  references yet (same-transaction reference check + `FOR UPDATE` row lock);
  disable is idempotent and never deletes bytes.
- Every action is audit-trailed (FILE_UPLOADED / _DOWNLOADED / _VERIFIED /
  _INTEGRITY_LOST / _DISABLED).

## 2. Business reports & controlled printing (`app/gsp/reports/`)

- Declarative reports with explicit, versioned output columns and a role ACL
  (no ORM introspection, so new columns can never leak into a controlled
  template).
- Production reports: electronic-signature and audit-event ledgers
  (AUDITOR/quality roles). Development previews (`production_ready=false`):
  batch stock, environment alarm and quality hold ledgers.
- `GET /api/gsp/reports` lists only visible reports; `GET /api/gsp/reports/{key}`
  pages with offset/limit/total/has_more and rejects unknown filters (422).
- `POST /api/gsp/reports/{key}/print`: production reports print as controlled;
  previews require explicit `preview=true` (else 409), are numbered `PREVIEW-`,
  use the `REPORT_PREVIEW_PRINTED` audit action and carry a per-page
  non-controlled watermark. `cover_all` reads all matches in one
  SELECT (MAX_ROWS+1) and refuses to exceed the cap.
- The controlled number / template version / filters / range are rendered into
  the HTML *before* hashing. Records persist the full HTML + normalised rows in
  `gsp_controlled_print_records`; `content_hash` covers the complete canonical
  snapshot, and `POST /prints/{id}/verify` cross-checks outer columns and
  recomputes the hash.
- Frontend (WMS-frontend): NAV 系统与合规 → 业务报表 reports centre; the four
  qualification forms upload controlled attachments via `uploadControlledFile`.
