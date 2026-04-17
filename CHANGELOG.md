# Changelog

All notable changes to `@attestto/pdf` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-10

### Added
- Initial release: PDF reader, PAdES-B signer, and signature verifier.
- **Reader:** `loadPdf()` extracts metadata (pages, title, author, dates, size) and computes SHA-256. `hashPdf()` for standalone hashing.
- **Signer:** `signPdf()` creates PAdES-B detached PKCS#7 signatures with pluggable signing callback. `createP12Signer()` extracts keys from PKCS#12 containers. Optional Solana anchor callback for PAdES-T timestamps.
- **Verifier:** `verifyPdf()` validates existing signatures — certificate extraction, expiry checking, document integrity validation.
- **Vue components:** `PdfViewer` (page navigation, zoom, dynamic worker loading) and `SignaturePanel` (signature card display, verification status, action buttons) exported via `@attestto/pdf/vue`.
- Dual ESM/CJS build via tsup.
- Test suite: 39 tests covering reader, signer (P12 extraction, signing flow, metadata, anchor), and verifier (unsigned PDFs, certificate info, roundtrip sign→verify).
- CI workflow for lint, test, build.
