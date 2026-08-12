# Changelog

All notable changes to `@attestto/pdf` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **A valid signature was rejected about 1 time in 8, decided by the value of its last nibble.** `findSignatures()` recovered the CMS from the `/Contents` window with `hex.replace(/0+$/, '')`, which cannot tell a padding zero from a signature byte that happens to be zero. Whenever the DER ended on a zero nibble the trim cut into the signature, leaving an odd-length hex string and a truncated structure, and `verifyPdf()` reported **0 signatures for a document it had just signed**. Measured on freshly signed PDFs: 4 of 30 rejected, every bad case an odd 2499 hex characters against a correct 2500. DER is self-describing, so the CMS length is now read from the outer SEQUENCE header and exactly that many bytes are taken. This fails closed (a valid document was rejected, never the reverse), but it made the verifier unreliable on correct input.
- **16 open Dependabot advisories closed, one of them critical.** `vitest` below 3.2.6 exposes an arbitrary file read while its UI server is listening (critical). The other 15 are transitive dependencies of the test toolchain: `brace-expansion` (3 DoS advisories), `js-yaml` (3 quadratic-CPU advisories), `nanoid` (2 infinite-loop advisories), `postcss` (4, including arbitrary file read through source-map auto-loading), `vite` (2), and `esbuild` (1).
- `vitest` moves from `^3.0.0` to `^3.2.6`. The old range already permitted the patched release: **the lockfile was pinning 3.2.4**, so no range change was ever needed and no dependency bot could have fixed it by widening one.
- The 6 transitive packages are held by bounded `overrides`, each floor set to the advisory's first patched version and each capped to its own major line. An open-ended floor adopts the next major silently, which is how a `js-yaml` floor elsewhere in this estate pulled in 5.x while still satisfying the advisory.
- All resolved versions verified individually against their advisory floor, not inferred from `npm audit` reporting zero. 53 tests pass and the build is clean.

### Added
- `scripts/gate-self-test.mjs`, byte-identical to the copy in the rest of the estate. It seeds a violation of each gate and requires a non-zero exit, so "the step is present" stops counting as evidence. It reported 6 problems on first run, all of them real, and all fixed here.
- `scripts/ci-changelog.mjs`, the changelog discipline gate.
- `eslint.config.js`. The `lint` script has existed since the first commit with **no config file and no TypeScript plugin installed**, so it exited 2 on every invocation for the life of the repo. It found 2 unused imports on its first real run.
- `tsconfig.test.json` and a CI step that type-checks the tests, which `tsconfig.json` excludes. A type error inside a spec was invisible.
- `.github/dependabot.yml`. Alerts were on and remediation was not, so 16 advisories accumulated with nothing opening a fix.

### Changed
- `typecheck` now runs `vue-tsc` instead of `tsc`, so the two Vue SFCs are type-checked. Under `tsc` they were unresolvable module imports and `typecheck` exited 2, which is why `prepublishOnly` (`lint && typecheck && test && build`) could never reach `test` or `build`. **A gate that cannot pass is not a gate**, and this package could not have been published without `--ignore-scripts`.
- CI triggers on every branch. With `branches: [main, develop]`, a pull request based on any other branch ran **no job at all**, so every step was skipped rather than failed.
- The `Lint` step no longer carries `continue-on-error: true`. It was added on the grounds that flat config was "not set up yet", and it never was, so the annotation read as a known-yellow rather than as a step that could not fail the build.

## [0.2.0] - 2026-07-19

Security release. The verifier previously reported a hard-coded integrity result, trusted the signature `ByteRange` as-parsed, accepted any unexpired certificate as trusted, and never checked revocation, so a tampered, appended, impersonated, or revoked-certificate document could verify as valid. Verification is now real and fail-closed across all four axes.

### Security
- **Real CMS signature verification** (verifier). `verifyPdf()` now cryptographically verifies each PKCS#7/CMS signature: the `messageDigest` signed attribute must equal the SHA-256 of the covered bytes, and the signature must verify over the DER-encoded `SignedAttributes` against the certificate's public key. Any missing element, digest mismatch, or bad signature fails closed. Replaces the previous placeholder that only checked digest length.
- **ByteRange coverage validation** (verifier). A signature is now accepted only when its `ByteRange` covers the whole document: it starts at byte 0, skips exactly the `/Contents` window, and reaches EOF with no unsigned trailing bytes. Detects incremental-update / append attacks and crafted ByteRanges that exclude content. Coverage is required on *every* signature, which also blocks appending a fresh full-coverage signature after a partial one.
- **Certificate chain / trust-anchor validation** (verifier). Passing `verifyPdf(pdf, { trustAnchors })` builds and validates the signer's chain to a pinned anchor; `SignatureInfo.chainStatus` reports `trusted` / `untrusted` / `unchecked`, and an `untrusted` result (anchors supplied, chain failed) forces the document invalid. Without `trustAnchors` the status is `unchecked` and the attacker-supplied subject is no longer implicitly trusted, it is surfaced, not asserted. Closes the CN-impersonation gap (e.g. a self-signed `CN="Banco Nacional CA"`).
- **Certificate revocation checking** (verifier). Passing `verifyPdf(pdf, { checkRevocation })` consults an injectable revocation checker; `SignatureInfo.revocationStatus` reports `good` / `revoked` / `unknown`. A `revoked` result forces the document invalid; a checker that throws degrades to `unknown` (surfaced, never silently treated as good). No network I/O by default, so consumers wire OCSP/CRL.

### Added
- `SignatureInfo.coversDocument: boolean`, whether the signature's `ByteRange` covers the entire file.
- `SignatureInfo.chainStatus: TrustStatus` and `SignatureInfo.revocationStatus: RevocationStatus`.
- `VerifyOptions` with `trustAnchors?: string[]` and `checkRevocation?` callback, passed as `verifyPdf(pdfBytes, options)`.
- Exported types `VerifyOptions`, `TrustStatus`, `RevocationStatus`, `RevocationQuery`.

### Changed
- **BREAKING (signer):** the signing callback is renamed `signHash` → `sign` and now receives the full signed content bytes (the `ByteRange` content) instead of a pre-computed hash. A CMS signer must digest the content itself so the `messageDigest` attribute binds the document. `createP12Signer()` returns the new `sign` callback. Update integrations that passed a `signHash` callback.
- `verifyPdf()` `valid` is now `true` only when every signature is cryptographically intact, in date, covers the document, is not known-revoked, and (when `trustAnchors` are supplied) chains to a trusted anchor.
- Signer header no longer advertises PAdES-T/LT as supported (only PAdES-B is implemented); the Solana `anchor` callback records a document-hash anchor, which is distinct from an RFC 3161 timestamp.

### Notes
- Out of scope for this release: built-in online OCSP/CRL fetching (needs network I/O; wire via `checkRevocation`) and true PAdES-LT (the signer does not yet emit a DSS). Trust-anchor validation and revocation are opt-in hooks, so a `valid: true` without `trustAnchors`/`checkRevocation` still means "intact, in-date, fully-covered," not "issued by a trusted, non-revoked authority."

## [0.1.0] - 2026-04-10

### Added
- Initial release: PDF reader, PAdES-B signer, and signature verifier.
- **Reader:** `loadPdf()` extracts metadata (pages, title, author, dates, size) and computes SHA-256. `hashPdf()` for standalone hashing.
- **Signer:** `signPdf()` creates PAdES-B detached PKCS#7 signatures with pluggable signing callback. `createP12Signer()` extracts keys from PKCS#12 containers. Optional Solana anchor callback for PAdES-T timestamps.
- **Verifier:** `verifyPdf()` validates existing signatures: certificate extraction, expiry checking, document integrity validation.
- **Vue components:** `PdfViewer` (page navigation, zoom, dynamic worker loading) and `SignaturePanel` (signature card display, verification status, action buttons) exported via `@attestto/pdf/vue`.
- Dual ESM/CJS build via tsup.
- Test suite: 39 tests covering reader, signer (P12 extraction, signing flow, metadata, anchor), and verifier (unsigned PDFs, certificate info, roundtrip sign→verify).
- CI workflow for lint, test, build.
