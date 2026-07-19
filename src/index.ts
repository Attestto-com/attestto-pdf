/**
 * @attestto/pdf — PDF engine for Attestto
 *
 * Read, sign (PAdES-B/T/LT), verify, and hash PDF documents.
 *
 * @example
 * ```ts
 * import { loadPdf, signPdf, verifyPdf, createP12Signer } from '@attestto/pdf'
 *
 * // Load and inspect
 * const { metadata } = await loadPdf(pdfBytes)
 * console.log(metadata.sha256, metadata.pageCount)
 *
 * // Sign with P12 certificate
 * const signer = createP12Signer(p12Buffer, 'password')
 * const signed = await signPdf(pdfBytes, {
 *   identity: { certificatePem: cert },
 *   sign: signer,
 * })
 *
 * // Verify
 * const result = await verifyPdf(signed.pdf)
 * console.log(result.valid, result.signatures)
 * ```
 */

export { loadPdf, hashPdf } from './reader.js'
export type { PdfMetadata, PdfLoadResult } from './reader.js'

export { signPdf, createP12Signer } from './signer.js'
export type { SigningIdentity, SignOptions, SignResult } from './signer.js'

export { verifyPdf } from './verifier.js'
export type {
  SignatureInfo,
  VerifyResult,
  VerifyOptions,
  RevocationStatus,
  RevocationQuery,
  TrustStatus,
} from './verifier.js'
