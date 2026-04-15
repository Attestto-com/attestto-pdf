# @attestto/pdf

PDF engine for the [Attestto](https://attestto.org) identity infrastructure. Read, sign, verify, and hash PDF documents with PAdES digital signatures and optional Solana anchoring.

**[Documentation](https://attestto.org/docs)** · **[Attestto Verify](https://www.npmjs.com/package/@attestto/verify)**

## Features

- **Read** — Load PDFs, extract metadata (title, author, pages), compute SHA-256 hash
- **Sign** — PAdES-B digital signatures (PKCS#7/CMS detached), P12/PFX certificate support
- **Verify** — Validate existing signatures: integrity, certificate validity, ByteRange checks
- **Anchor** — Optional Solana timestamp anchoring (PAdES-T) via callback
- **Vue components** — `<PdfViewer>` and `<SignaturePanel>` (optional, requires Vue 3.4+)

## Install

```bash
npm install @attestto/pdf
```

## Quick start

### Load and inspect a PDF

```typescript
import { loadPdf } from '@attestto/pdf'

const pdfBytes = await fs.readFile('document.pdf')
const { metadata } = await loadPdf(pdfBytes)

console.log(metadata.sha256)      // SHA-256 hash
console.log(metadata.pageCount)   // Number of pages
console.log(metadata.title)       // PDF title
```

### Sign with a P12 certificate

```typescript
import { signPdf, createP12Signer } from '@attestto/pdf'

const p12 = await fs.readFile('certificate.p12')
const signHash = createP12Signer(p12, 'password')

const result = await signPdf(pdfBytes, {
  identity: { certificatePem: cert },
  signHash,
  reason: 'Document approval',
  location: 'San Jose, CR',
})

await fs.writeFile('signed.pdf', result.pdf)
console.log('Signed:', result.sha256)
```

### Sign with Solana anchor (PAdES-T)

```typescript
const result = await signPdf(pdfBytes, {
  identity: { certificatePem: cert, did: 'did:sns:notario.go-cr.sol' },
  signHash,
  anchor: async (docHash) => {
    // Your Solana anchoring logic
    return transactionId
  },
})

console.log('Anchored:', result.anchorTxId)
```

### Verify signatures

```typescript
import { verifyPdf } from '@attestto/pdf'

const result = await verifyPdf(signedPdfBytes)

console.log('Valid:', result.valid)
console.log('Signatures:', result.signatureCount)

for (const sig of result.signatures) {
  console.log(sig.signerName)      // CN from certificate
  console.log(sig.certIssuer)      // Issuing CA
  console.log(sig.certValid)       // Not expired
  console.log(sig.integrityValid)  // Document not tampered
}
```

## API

### Reader

| Function | Returns | Description |
|---|---|---|
| `loadPdf(bytes)` | `PdfLoadResult` | Load PDF, extract metadata, compute hash |
| `hashPdf(bytes)` | `string` | SHA-256 hash of raw PDF bytes |

### Signer

| Function | Returns | Description |
|---|---|---|
| `signPdf(bytes, options)` | `SignResult` | Sign PDF with PAdES-B signature |
| `createP12Signer(p12, password)` | `(hash) => Promise<Buffer>` | Create signing callback from P12/PFX certificate |

**SignOptions:**

| Property | Type | Description |
|---|---|---|
| `identity` | `SigningIdentity` | Certificate PEM + optional chain + optional DID |
| `signHash` | `(hash: Buffer) => Promise<Buffer>` | Signing callback (P12, PKCS#11, WebAuthn) |
| `reason` | `string?` | Reason for signing |
| `location` | `string?` | Signing location |
| `anchor` | `(hash: string) => Promise<string>?` | Solana anchor callback |

### Verifier

| Function | Returns | Description |
|---|---|---|
| `verifyPdf(bytes)` | `VerifyResult` | Verify all signatures in a PDF |

**VerifyResult:**

| Property | Type | Description |
|---|---|---|
| `valid` | `boolean` | All signatures valid, no tampering |
| `signatureCount` | `number` | Number of signatures found |
| `signatures` | `SignatureInfo[]` | Per-signature details |
| `errors` | `string[]` | Error messages |

## Vue components

Optional Vue 3 components for PDF rendering and signature display:

```typescript
import { PdfViewer, SignaturePanel } from '@attestto/pdf/vue'
```

Requires `pdfjs-dist` and `vue` as peer dependencies.

## Architecture

The signer never holds private keys. It receives a `signHash` callback, which means you can plug in:

- **P12/PFX certificates** — via `createP12Signer()`
- **PKCS#11 smart cards** — wrap your PKCS#11 library in the callback
- **WebAuthn/FIDO** — browser-based signing
- **Remote HSM** — call your signing service

```
PDF bytes → loadPdf() → metadata + hash
         → signPdf() → signHash callback → PKCS#7 → embed in PDF → optional Solana anchor
         → verifyPdf() → extract signatures → validate integrity + certs
```

## Ecosystem

| Package | Role |
|---|---|
| [`@attestto/verify`](https://www.npmjs.com/package/@attestto/verify) | Document verification Web Components |
| [`@attestto/login`](https://www.npmjs.com/package/@attestto/login) | DID login Web Component |
| [`attestto-trust`](https://github.com/Attestto-com/attestto-trust) | PKI trust store — CA certificates by country |

## License

UNLICENSED (internal — not yet published to npm)
