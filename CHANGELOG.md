# Changelog

All notable changes to `@attestto/pdf` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-19

Security release. The verifier previously reported a hard-coded integrity result, trusted the signature `ByteRange` as-parsed, accepted any unexpired certificate as trusted, and never checked revocation — so a tampered, appended, impersonated, or revoked-certificate document could verify as valid. Verification is now real and fail-closed across all four axes.

### Security
- **Real CMS signature verification** (verifier). `verifyPdf()` now cryptographically verifies each PKCS#7/CMS signature: the `messageDigest` signed attribute must equal the SHA-256 of the covered bytes, and the signature must verify over the DER-encoded `SignedAttributes` against the certificate's public key. Any missing element, digest mismatch, or bad signature fails closed. Replaces the previous placeholder that only checked digest length.
- **ByteRange coverage validation** (verifier). A signature is now accepted only when its `ByteRange` covers the whole document — starts at byte 0, skips exactly the `/Contents` window, and reaches EOF with no unsigned trailing bytes. Detects incremental-update / append attacks and crafted ByteRanges that exclude content. Coverage is required on *every* signature, which also blocks appending a fresh full-coverage signature after a partial one.
- **Certificate chain / trust-anchor validation** (verifier). Passing `verifyPdf(pdf, { trustAnchors })` builds and validates the signer's chain to a pinned anchor; `SignatureInfo.chainStatus` reports `trusted` / `untrusted` / `unchecked`, and an `untrusted` result (anchors supplied, chain failed) forces the document invalid. Without `trustAnchors` the status is `unchecked` and the attacker-supplied subject is no longer implicitly trusted — it is surfaced, not asserted. Closes the CN-impersonation gap (e.g. a self-signed `CN="Banco Nacional CA"`).
- **Certificate revocation checking** (verifier). Passing `verifyPdf(pdf, { checkRevocation })` consults an injectable revocation checker; `SignatureInfo.revocationStatus` reports `good` / `revoked` / `unknown`. A `revoked` result forces the document invalid; a checker that throws degrades to `unknown` (surfaced, never silently treated as good). No network I/O by default — consumers wire OCSP/CRL.

### Added
- `SignatureInfo.coversDocument: boolean` — whether the signature's `ByteRange` covers the entire file.
- `SignatureInfo.chainStatus: TrustStatus` and `SignatureInfo.revocationStatus: RevocationStatus`.
- `VerifyOptions` with `trustAnchors?: string[]` and `checkRevocation?` callback, passed as `verifyPdf(pdfBytes, options)`.
- Exported types `VerifyOptions`, `TrustStatus`, `RevocationStatus`, `RevocationQuery`.

### Changed
- **BREAKING (signer):** the signing callback is renamed `signHash` → `sign` and now receives the full signed content bytes (the `ByteRange` content) instead of a pre-computed hash. A CMS signer must digest the content itself so the `messageDigest` attribute binds the document. `createP12Signer()` returns the new `sign` callback. Update integrations that passed a `signHash` callback.
- `verifyPdf()` `valid` is now `true` only when every signature is cryptographically intact, in date, covers the document, is not known-revoked, and — when `trustAnchors` are supplied — chains to a trusted anchor.
- Signer header no longer advertises PAdES-T/LT as supported (only PAdES-B is implemented); the Solana `anchor` callback records a document-hash anchor, which is distinct from an RFC 3161 timestamp.

### Notes
- Out of scope for this release: built-in online OCSP/CRL fetching (needs network I/O; wire via `checkRevocation`) and true PAdES-LT (the signer does not yet emit a DSS). Trust-anchor validation and revocation are opt-in hooks — a `valid: true` without `trustAnchors`/`checkRevocation` still means "intact, in-date, fully-covered," not "issued by a trusted, non-revoked authority."

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
