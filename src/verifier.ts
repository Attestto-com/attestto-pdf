/**
 * PDF Verifier — Validate existing PDF signatures
 *
 * Checks:
 * - Signature integrity (CMS signature over SignedAttributes + messageDigest)
 * - Document coverage (ByteRange covers the whole file; no appended bytes)
 * - Certificate validity window (not-before / not-after)
 * - Certificate revocation — ONLY when a `checkRevocation` callback is supplied
 *   (no network I/O by default)
 *
 * Certificate chain / trust-anchor validation runs ONLY when `trustAnchors` are
 * supplied (the library ships no built-in trust store). Without them, trust is
 * `'unchecked'` and a `valid: true` result means "intact, in-date, fully
 * covered, and not known-revoked" — NOT "issued by a trusted authority." With
 * anchors, a signer whose chain does not validate forces the document invalid.
 */

import { PDFDocument } from 'pdf-lib'
import forge from 'node-forge'
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'

/** Certificate revocation status for a signer certificate. */
export type RevocationStatus = 'good' | 'revoked' | 'unknown'

/**
 * Trust-chain status for a signer certificate.
 * - `'trusted'`   — the chain built to one of the supplied trust anchors.
 * - `'untrusted'` — anchors were supplied but the chain did not validate.
 * - `'unchecked'` — no trust anchors were supplied.
 */
export type TrustStatus = 'trusted' | 'untrusted' | 'unchecked'

/** Inputs handed to a revocation checker for one signer certificate. */
export interface RevocationQuery {
  /** PEM-encoded signer certificate. */
  signerCertPem: string
  /** Signer certificate serial number. */
  serialNumber: string
  /** Signer certificate issuer common name. */
  issuerCN: string
}

export interface VerifyOptions {
  /**
   * Optional certificate-revocation checker. The library performs NO network
   * I/O by default — provide this to check the signer certificate via OCSP
   * (with CRL fallback) or against embedded/pinned revocation data. Return
   * `'revoked'` to invalidate the signature, `'good'` to confirm it is not
   * revoked, or `'unknown'` when the status cannot be determined. A checker
   * that throws is treated as `'unknown'`.
   */
  checkRevocation?: (query: RevocationQuery) => Promise<RevocationStatus>

  /**
   * PEM-encoded trusted root/intermediate certificates (pinned trust anchors,
   * e.g. from an `attestto-trust` mirror). When supplied, the signer's chain —
   * built from the signer cert plus any intermediates embedded in the PKCS#7 —
   * is validated up to one of these anchors, and the signer's key usage is
   * checked for document signing. When omitted, trust is not evaluated
   * (`chainStatus: 'unchecked'`); the library ships no built-in trust store.
   */
  trustAnchors?: string[]
}

export interface SignatureInfo {
  /** Signer common name from certificate */
  signerName: string
  /** Signing reason */
  reason?: string
  /** Signing location */
  location?: string
  /** Signing time */
  signedAt?: Date
  /** Certificate serial number */
  certSerial: string
  /** Certificate issuer CN */
  certIssuer: string
  /** Certificate valid from */
  certValidFrom: Date
  /** Certificate valid to */
  certValidTo: Date
  /** Whether the certificate is currently valid (not expired) */
  certValid: boolean
  /** Whether the document was modified after signing */
  integrityValid: boolean
  /**
   * Whether the signature's ByteRange covers the entire document — it starts at
   * byte 0, skips exactly the signature `Contents` window, and reaches EOF with
   * no unsigned trailing bytes. `false` means a partial signature or an
   * incremental-update / append modification that the signature does not cover.
   */
  coversDocument: boolean
  /**
   * Certificate revocation status. `'unknown'` when no `checkRevocation`
   * callback was supplied (the library does not fetch OCSP/CRL by default).
   * A `'revoked'` status forces the signature — and the document — invalid.
   */
  revocationStatus: RevocationStatus
  /**
   * Trust-chain status. `'unchecked'` when no `trustAnchors` were supplied.
   * `'untrusted'` (chain did not build to a supplied anchor, or key usage is
   * wrong) forces the signature — and the document — invalid.
   */
  chainStatus: TrustStatus
  /** Raw DER signature bytes */
  signatureBytes: Buffer
}

export interface VerifyResult {
  /** Number of signatures found */
  signatureCount: number
  /** Details for each signature */
  signatures: SignatureInfo[]
  /** Overall validity — all signatures valid and no tampering */
  valid: boolean
  /** Errors found */
  errors: string[]
}

/**
 * Verify all signatures in a PDF document.
 */
export async function verifyPdf(
  pdfBytes: Uint8Array | Buffer,
  options?: VerifyOptions
): Promise<VerifyResult> {
  const bytes = pdfBytes instanceof Buffer ? new Uint8Array(pdfBytes) : pdfBytes
  const pdfBuffer = Buffer.from(bytes)

  const signatures: SignatureInfo[] = []
  const errors: string[] = []

  // Find all signature Contents in the PDF
  const sigLocations = findSignatures(pdfBuffer)

  for (const sig of sigLocations) {
    try {
      const info = await verifySignature(pdfBuffer, sig, options)
      signatures.push(info)
    } catch (err) {
      errors.push(`Signature verification failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  return {
    signatureCount: signatures.length,
    signatures,
    // A document is valid only if every signature is cryptographically intact,
    // its certificate is in date, covers the whole file, is not known-revoked,
    // and — when trust anchors were supplied — chains to a trusted anchor.
    // Requiring every signature to cover the document (not just one) also blocks
    // the bypass of appending a fresh full-coverage signature after a partial
    // one. A 'trusted' or 'unchecked' chain does not block validity; only an
    // explicit 'untrusted' (anchors supplied, chain failed) does.
    valid:
      signatures.length > 0 &&
      signatures.every(
        (s) =>
          s.integrityValid &&
          s.certValid &&
          s.coversDocument &&
          s.revocationStatus !== 'revoked' &&
          s.chainStatus !== 'untrusted'
      ) &&
      errors.length === 0,
    errors,
  }
}

interface SignatureLocation {
  contentsHex: string
  byteRange?: number[]
  /** Byte offset of the '<' opening the Contents hex window. */
  contentsStart: number
  /** Byte offset just after the '>' closing the Contents hex window. */
  contentsEnd: number
}

function findSignatures(pdf: Buffer): SignatureLocation[] {
  const results: SignatureLocation[] = []
  const pdfStr = pdf.toString('latin1')

  // Find /Contents <hex> patterns that are part of signature dictionaries.
  // latin1 is 1 byte per char, so match indices are byte offsets.
  const contentsRegex = /\/Contents\s*<([0-9a-fA-F]+)>/g
  let match: RegExpExecArray | null

  while ((match = contentsRegex.exec(pdfStr)) !== null) {
    // Look for /SubFilter /adbe.pkcs7.detached nearby to confirm it's a signature
    const contextStart = Math.max(0, match.index - 500)
    const context = pdfStr.substring(contextStart, match.index + match[0].length + 100)

    if (context.includes('adbe.pkcs7.detached') || context.includes('ETSI.CAdES.detached')) {
      // Extract ByteRange if present
      const brMatch = context.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/)
      const byteRange = brMatch
        ? [parseInt(brMatch[1]), parseInt(brMatch[2]), parseInt(brMatch[3]), parseInt(brMatch[4])]
        : undefined

      results.push({
        contentsHex: match[1].replace(/0+$/, ''), // Trim padding zeros
        byteRange,
        contentsStart: match.index + match[0].indexOf('<'),
        contentsEnd: match.index + match[0].length, // just after '>'
      })
    }
  }

  return results
}

/**
 * Validate that a signature's ByteRange actually covers the whole document.
 *
 * A well-formed PAdES ByteRange is `[0, contentsStart, contentsEnd, len - contentsEnd]`:
 * it must start at byte 0, skip exactly the `/Contents <...>` hex window (and
 * nothing else), and extend to the end of the file. If the second segment does
 * not reach EOF, bytes were appended after signing (incremental-update / append
 * attack) and those bytes are NOT covered by the signature.
 */
function byteRangeCoversDocument(
  byteRange: number[] | undefined,
  contentsStart: number,
  contentsEnd: number,
  fileLength: number
): boolean {
  if (!byteRange || byteRange.length !== 4) return false
  const [o1, l1, o2, l2] = byteRange
  if ([o1, l1, o2, l2].some((n) => !Number.isInteger(n) || n < 0)) return false
  return (
    o1 === 0 &&
    o1 + l1 === contentsStart && // first segment ends exactly at the '<'
    o2 === contentsEnd && //          second segment starts exactly after the '>'
    o2 + l2 === fileLength //         and reaches EOF — no unsigned appended bytes
  )
}

async function verifySignature(
  pdf: Buffer,
  sig: SignatureLocation,
  options?: VerifyOptions
): Promise<SignatureInfo> {
  // Decode the PKCS#7 signature
  const sigDer = Buffer.from(sig.contentsHex, 'hex')
  const asn1 = forge.asn1.fromDer(sigDer.toString('binary'))
  const p7 = forge.pkcs7.messageFromAsn1(asn1) as forge.pkcs7.PkcsSignedData

  // Extract signer info
  const signerCert = p7.certificates?.[0] as forge.pki.Certificate | undefined
  if (!signerCert) {
    throw new Error('No certificate found in PKCS#7 signature')
  }

  const now = new Date()
  const certValid =
    signerCert.validity.notBefore <= now && now <= signerCert.validity.notAfter

  // Verify cryptographic integrity: the signer's signature must verify over the
  // SignedAttributes, and the messageDigest attribute must equal the SHA-256 of
  // the ByteRange content. Fail closed — a missing ByteRange, missing signed
  // attributes, a mismatched digest, or a bad signature all yield `false`.
  let integrityValid = false
  if (sig.byteRange) {
    const [offset1, length1, offset2, length2] = sig.byteRange
    const signedData = Buffer.concat([
      pdf.subarray(offset1, offset1 + length1),
      pdf.subarray(offset2, offset2 + length2),
    ])
    integrityValid = verifyCmsIntegrity(p7, signerCert, signedData)
  }

  // Validate that the ByteRange covers the whole file (detects append /
  // incremental-update attacks and crafted ByteRanges that exclude bytes).
  const coversDocument = byteRangeCoversDocument(
    sig.byteRange,
    sig.contentsStart,
    sig.contentsEnd,
    pdf.length
  )

  // Revocation: the library does no network I/O by default. When a checker is
  // supplied, consult it; a thrown checker is treated as 'unknown' (fail-safe
  // to not-known-revoked, surfaced explicitly rather than silently ignored).
  let revocationStatus: RevocationStatus = 'unknown'
  if (options?.checkRevocation) {
    try {
      revocationStatus = await options.checkRevocation({
        signerCertPem: forge.pki.certificateToPem(signerCert),
        serialNumber: signerCert.serialNumber,
        issuerCN: signerCert.issuer.getField('CN')?.value || 'Unknown',
      })
    } catch {
      revocationStatus = 'unknown'
    }
  }

  // Trust chain: only evaluated when the caller pins trust anchors. Build the
  // chain from the signer cert plus any intermediates embedded in the PKCS#7.
  let chainStatus: TrustStatus = 'unchecked'
  if (options?.trustAnchors && options.trustAnchors.length > 0) {
    const intermediates = (p7.certificates ?? []).slice(1) as forge.pki.Certificate[]
    chainStatus = validateChain(signerCert, intermediates, options.trustAnchors)
      ? 'trusted'
      : 'untrusted'
  }

  // Signing time extraction (from authenticated attributes) — deferred to v0.2
  const signedAt: Date | undefined = undefined

  return {
    signerName: signerCert.subject.getField('CN')?.value || 'Unknown',
    reason: undefined, // Extracted from sig dict, not PKCS#7
    location: undefined,
    signedAt,
    certSerial: signerCert.serialNumber,
    certIssuer: signerCert.issuer.getField('CN')?.value || 'Unknown',
    certValidFrom: signerCert.validity.notBefore,
    certValidTo: signerCert.validity.notAfter,
    certValid,
    integrityValid,
    coversDocument,
    revocationStatus,
    chainStatus,
    signatureBytes: sigDer,
  }
}

/**
 * Build and validate the signer certificate chain against pinned trust anchors,
 * and check that the signer's key usage permits document signing.
 *
 * Returns true only if the chain builds from the signer cert (plus embedded
 * intermediates) to one of the trust anchors with valid signatures and dates,
 * and the leaf's keyUsage (when present) allows digitalSignature/nonRepudiation.
 * Any parse/verify failure returns false (fail closed).
 */
function validateChain(
  signerCert: forge.pki.Certificate,
  intermediates: forge.pki.Certificate[],
  trustAnchorsPem: string[]
): boolean {
  try {
    // Key usage: if the extension is present it must permit signing.
    const keyUsage = signerCert.getExtension('keyUsage') as
      | { digitalSignature?: boolean; nonRepudiation?: boolean }
      | undefined
    if (keyUsage && !keyUsage.digitalSignature && !keyUsage.nonRepudiation) {
      return false
    }

    const anchors = trustAnchorsPem.map((pem) => forge.pki.certificateFromPem(pem))
    const caStore = forge.pki.createCaStore(anchors)
    const chain = [signerCert, ...intermediates]

    // Throws on any failure (broken signature, expired, not reaching an anchor).
    return forge.pki.verifyCertificateChain(caStore, chain) === true
  } catch {
    return false
  }
}

/** Map a digest-algorithm OID to a Node crypto hash name. */
function digestOidToHashName(oid: string): string | null {
  switch (oid) {
    case forge.pki.oids.sha256:
      return 'sha256'
    case forge.pki.oids.sha384:
      return 'sha384'
    case forge.pki.oids.sha512:
      return 'sha512'
    case forge.pki.oids.sha1:
      return 'sha1'
    default:
      return null
  }
}

/** Extract the raw value bytes of a signed attribute by OID, or null if absent. */
function findSignedAttribute(attrs: forge.asn1.Asn1[], oid: string): string | null {
  for (const attr of attrs) {
    // attr = SEQUENCE { attrType OID, attrValues SET }
    const seq = attr.value as forge.asn1.Asn1[]
    if (!Array.isArray(seq) || seq.length < 2) continue
    const attrOid = forge.asn1.derToOid(seq[0].value as string)
    if (attrOid !== oid) continue
    const valueSet = seq[1].value as forge.asn1.Asn1[]
    if (!Array.isArray(valueSet) || valueSet.length === 0) return null
    return valueSet[0].value as string
  }
  return null
}

/**
 * Verify the CMS/PKCS#7 signature over its SignedAttributes and confirm the
 * messageDigest attribute matches the SHA-256 of the signed ByteRange content.
 *
 * This is real cryptographic verification: it proves the document was not
 * modified after signing (messageDigest match) AND that the signature was
 * produced by the private key matching the certificate's public key (signature
 * over the DER-encoded SignedAttributes). Any missing element, digest mismatch,
 * or signature failure returns `false` (fail closed).
 *
 * Note: this does NOT establish that the certificate is trusted — chain
 * building / trust-anchor validation is tracked separately (SOC-30).
 */
function verifyCmsIntegrity(
  p7: forge.pkcs7.PkcsSignedData,
  signerCert: forge.pki.Certificate,
  signedData: Buffer
): boolean {
  try {
    const rawCapture = (p7 as unknown as { rawCapture?: Record<string, unknown> }).rawCapture
    const authenticatedAttributes = rawCapture?.authenticatedAttributes as forge.asn1.Asn1[] | undefined
    const signature = rawCapture?.signature as string | undefined
    const digestAlgorithmDer = rawCapture?.digestAlgorithm as string | undefined

    // PAdES/CMS signatures used here always carry SignedAttributes. If they are
    // absent — or the signature bytes are missing — we cannot verify: reject.
    if (!authenticatedAttributes || authenticatedAttributes.length === 0 || !signature) {
      return false
    }

    // Resolve the digest algorithm from the signerInfo; reject unknown algorithms.
    const hashName = digestAlgorithmDer
      ? digestOidToHashName(forge.asn1.derToOid(digestAlgorithmDer))
      : 'sha256'
    if (!hashName) return false

    // 1. messageDigest attribute must equal the hash of the actual ByteRange
    //    content. This is what detects post-signing tampering.
    const signedMessageDigest = findSignedAttribute(authenticatedAttributes, forge.pki.oids.messageDigest)
    if (!signedMessageDigest) return false
    const computedDigest = createHash(hashName).update(signedData).digest()
    if (!computedDigest.equals(Buffer.from(signedMessageDigest, 'binary'))) {
      return false
    }

    // 2. The signature must verify over the DER-encoded SignedAttributes. In the
    //    CMS structure they are IMPLICIT [0] tagged; the signature is computed
    //    over their re-encoding as an explicit SET OF (tag 0x31).
    const attrSet = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      authenticatedAttributes
    )
    const attrDer = Buffer.from(forge.asn1.toDer(attrSet).getBytes(), 'binary')
    const publicKey = createPublicKey(forge.pki.certificateToPem(signerCert))
    const signatureBytes = Buffer.from(signature, 'binary')

    // crypto.verify hashes `attrDer` with `hashName` and checks the signature —
    // RSASSA-PKCS1-v1_5 for RSA keys, ECDSA (DER) for EC keys.
    return cryptoVerify(hashName, attrDer, publicKey, signatureBytes)
  } catch {
    return false
  }
}
