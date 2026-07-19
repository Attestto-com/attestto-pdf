# Changelog

All notable changes to `@attestto/pdf` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-19

Security release. The verifier previously reported a hard-coded integrity result and trusted the signature `ByteRange` as-parsed, so a tampered or appended document could verify as valid. Verification is now real and fail-closed.

### Security
- **Real CMS signature verification** (verifier). `verifyPdf()` now cryptographically verifies each PKCS#7/CMS signature: the `messageDigest` signed attribute must equal the SHA-256 of the covered bytes, and the signature must verify over the DER-encoded `SignedAttributes` against the certificate's public key. Any missing element, digest mismatch, or bad signature fails closed. Replaces the previous placeholder that only checked digest length.
- **ByteRange coverage validation** (verifier). A signature is now accepted only when its `ByteRange` covers the whole document — starts at byte 0, skips exactly the `/Contents` window, and reaches EOF with no unsigned trailing bytes. Detects incremental-update / append attacks and crafted ByteRanges that exclude content. Coverage is required on *every* signature, which also blocks appending a fresh full-coverage signature after a partial one.

### Added
- `SignatureInfo.coversDocument: boolean` — whether the signature's `ByteRange` covers the entire file. `false` indicates a partial signature or a post-signing incremental update not covered by the signature.

### Changed
- **BREAKING (signer):** the signing callback is renamed `signHash` → `sign` and now receives the full signed content bytes (the `ByteRange` content) instead of a pre-computed hash. A CMS signer must digest the content itself so the `messageDigest` attribute binds the document. `createP12Signer()` returns the new `sign` callback. Update integrations that passed a `signHash` callback.
- `verifyPdf()` `valid` is now `true` only when every signature is cryptographically intact, in date, **and** covers the document.

### Notes
- Certificate *trust* (chain building / trust-anchor validation) is out of scope for this release and tracked separately — a valid signature here proves integrity and authorship by the embedded certificate, not that the certificate is trusted.

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
