/**
 * PDF Signer — PAdES-B digital signatures
 *
 * Implements:
 * - PAdES-B: CMS/PKCS#7 detached signature embedded in PDF
 *
 * Out of scope in this release — do not advertise these as supported until they
 * are built (see SOC-38):
 * - PAdES-T (trusted timestamp): the optional Solana `anchor` callback records a
 *   document-hash anchor, but that is distinct from an RFC 3161 signature
 *   timestamp and is neither embedded nor verified as PAdES-T.
 * - PAdES-LT (long-term validation): a DSS with the cert chain and a revocation
 *   snapshot is not produced, so revocation is not captured at signing time;
 *   verifiers must check revocation out of band.
 *
 * The signer does NOT hold private keys — it receives a signing callback.
 * This allows plugging in P12 certs, PKCS#11 smart cards, or WebAuthn.
 */

import { PDFDocument, PDFHexString, PDFName, PDFArray, PDFDict, PDFString, PDFNumber } from 'pdf-lib'
import forge from 'node-forge'
import { createHash } from 'node:crypto'

export interface SigningIdentity {
  /** PEM-encoded X.509 certificate */
  certificatePem: string
  /** PEM-encoded certificate chain (intermediates) */
  chainPem?: string[]
  /** DID of the signer (e.g., did:sns:notario.go-cr.sol) */
  did?: string
}

export interface SignOptions {
  /** Signing identity (certificate + optional chain) */
  identity: SigningIdentity
  /** Reason for signing */
  reason?: string
  /** Location of signing */
  location?: string
  /** Contact info */
  contactInfo?: string
  /**
   * Callback that produces the CMS signature. This is where PKCS#11 / P12 /
   * WebAuthn plugs in.
   *
   * Receives the exact bytes covered by the signature (the PDF ByteRange
   * content) and returns a DER-encoded **detached** PKCS#7/CMS signature whose
   * `messageDigest` authenticated attribute is `SHA-256(signedBytes)`. Passing
   * the content (not a bare hash) is required so the signature actually binds
   * the document — a CMS signer must digest the content itself.
   */
  sign: (signedBytes: Buffer) => Promise<Buffer>
  /**
   * Optional: anchor the signature timestamp on-chain.
   * Receives the document hash, returns a transaction ID or proof.
   */
  anchor?: (documentHash: string) => Promise<string>
}

export interface SignResult {
  /** Signed PDF bytes */
  pdf: Uint8Array
  /** SHA-256 of the signed PDF */
  sha256: string
  /** Solana anchor tx ID (if anchored) */
  anchorTxId?: string
}

/**
 * Sign a PDF with a PAdES-B signature.
 *
 * Flow:
 * 1. Add signature dictionary with ByteRange placeholder
 * 2. Compute the PDF ByteRange (excluding the signature placeholder)
 * 3. Call sign() with that content to get the PKCS#7/CMS signature
 * 4. Embed signature into the placeholder
 * 5. Optionally anchor on Solana
 */
export async function signPdf(
  pdfBytes: Uint8Array | Buffer,
  options: SignOptions
): Promise<SignResult> {
  const input = pdfBytes instanceof Buffer ? new Uint8Array(pdfBytes) : pdfBytes

  // Parse the certificate
  const cert = forge.pki.certificateFromPem(options.identity.certificatePem)

  // Load PDF
  const pdfDoc = await PDFDocument.load(input, { updateMetadata: false })

  // Create signature placeholder
  // Reserve 8192 bytes for the PKCS#7 signature (standard size)
  const signaturePlaceholderLength = 8192
  const placeholder = Buffer.alloc(signaturePlaceholderLength).toString('hex')

  // Add signature dictionary to the PDF
  // ByteRange placeholder: 10-digit numbers give enough space for real values later
  const byteRangePlaceholder = PDFArray.withContext(pdfDoc.context)
  byteRangePlaceholder.push(PDFNumber.of(0))
  byteRangePlaceholder.push(PDFNumber.of(9999999999))
  byteRangePlaceholder.push(PDFNumber.of(9999999999))
  byteRangePlaceholder.push(PDFNumber.of(9999999999))

  const sigDict = pdfDoc.context.obj({
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: 'adbe.pkcs7.detached',
    ByteRange: byteRangePlaceholder,
    Contents: PDFHexString.of(placeholder),
    Reason: options.reason ? PDFString.of(options.reason) : undefined,
    Location: options.location ? PDFString.of(options.location) : undefined,
    ContactInfo: options.contactInfo ? PDFString.of(options.contactInfo) : undefined,
    M: PDFString.of(formatPdfDate(new Date())),
    Name: PDFString.of(cert.subject.getField('CN')?.value || 'Attestto Signer'),
  })

  // Add signature field to the first page's annotations
  const pages = pdfDoc.getPages()
  const firstPage = pages[0]

  const sigFieldDict = pdfDoc.context.obj({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: [0, 0, 0, 0], // Invisible signature
    V: sigDict,
    T: PDFString.of('AttesttoSignature'),
    F: 4, // Print flag
    P: firstPage.ref,
  })

  const sigFieldRef = pdfDoc.context.register(sigFieldDict)

  // Add to page annotations
  const annots = firstPage.node.get(PDFName.of('Annots'))
  if (annots instanceof PDFArray) {
    annots.push(sigFieldRef)
  } else {
    firstPage.node.set(PDFName.of('Annots'), pdfDoc.context.obj([sigFieldRef]))
  }

  // Add to AcroForm
  const acroForm = pdfDoc.catalog.getOrCreateAcroForm()
  acroForm.addField(sigFieldRef)

  // Save with placeholder
  const pdfWithPlaceholder = await pdfDoc.save({ useObjectStreams: false })

  // Step 1: Locate the Contents hex string to compute ByteRange
  const pdfBuffer = Buffer.from(pdfWithPlaceholder)
  const contentsTag = Buffer.from('/Contents <')
  const contentsStart = pdfBuffer.indexOf(contentsTag)

  if (contentsStart === -1) {
    throw new Error('Could not locate signature Contents placeholder in PDF')
  }

  const hexStart = contentsStart + contentsTag.length - 1 // Position of '<'
  const hexEnd = pdfBuffer.indexOf(Buffer.from('>'), hexStart) + 1

  // ByteRange: [0, hexStart, hexEnd, pdfBuffer.length - hexEnd]
  const byteRange = [0, hexStart, hexEnd, pdfBuffer.length - hexEnd]

  // Step 2: Patch ByteRange placeholder with real values BEFORE hashing
  const brPlaceholderRegex = /\/ByteRange\s*\[\s*0\s+9999999999\s+9999999999\s+9999999999\s*\]/
  const pdfStr = pdfBuffer.toString('latin1')
  const brMatch = brPlaceholderRegex.exec(pdfStr)
  if (brMatch) {
    const byteRangeStr = `/ByteRange [${byteRange[0]} ${byteRange[1]} ${byteRange[2]} ${byteRange[3]}]`
    const padded = byteRangeStr.padEnd(brMatch[0].length, ' ')
    Buffer.from(padded, 'latin1').copy(pdfBuffer, brMatch.index)
  }

  // Step 3: Collect the bytes covered by the signature (everything outside the
  // Contents placeholder). These are what the CMS signature must bind.
  const signedContent = Buffer.concat([
    pdfBuffer.subarray(byteRange[0], byteRange[0] + byteRange[1]),
    pdfBuffer.subarray(byteRange[2], byteRange[2] + byteRange[3]),
  ])

  // Step 4: Produce the detached PKCS#7/CMS signature over that content.
  const pkcs7Signature = await options.sign(signedContent)

  // Verify the signature fits in the placeholder
  const sigHex = pkcs7Signature.toString('hex')
  if (sigHex.length > signaturePlaceholderLength * 2) {
    throw new Error(
      `Signature too large: ${sigHex.length / 2} bytes, placeholder is ${signaturePlaceholderLength} bytes`
    )
  }

  // Pad the signature hex to fill the placeholder
  const paddedSigHex = sigHex.padEnd(signaturePlaceholderLength * 2, '0')

  // Step 5: Embed signature into the placeholder
  const signedPdf = Buffer.from(pdfBuffer)
  const placeholderHex = Buffer.from(placeholder)
  const placeholderPos = signedPdf.indexOf(placeholderHex, hexStart)
  if (placeholderPos === -1) {
    throw new Error('Could not locate hex placeholder in PDF')
  }
  Buffer.from(paddedSigHex).copy(signedPdf, placeholderPos)

  const sha256 = createHash('sha256').update(signedPdf).digest('hex')

  // Optional: anchor on Solana
  let anchorTxId: string | undefined
  if (options.anchor) {
    anchorTxId = await options.anchor(sha256)
  }

  return {
    pdf: new Uint8Array(signedPdf),
    sha256,
    anchorTxId,
  }
}

/**
 * Create a PKCS#7/CMS signer from a P12/PFX certificate.
 * Returns a `sign` callback for use with signPdf().
 */
export function createP12Signer(
  p12Buffer: Buffer,
  password: string
): (signedBytes: Buffer) => Promise<Buffer> {
  const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'))
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password)

  // Extract private key
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]
  if (!keyBag?.key) throw new Error('No private key found in P12')
  const privateKey = keyBag.key

  // Extract certificate
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })
  const certBag = certBags[forge.pki.oids.certBag]?.[0]
  if (!certBag?.cert) throw new Error('No certificate found in P12')
  const cert = certBag.cert

  return async (signedBytes: Buffer): Promise<Buffer> => {
    // Create PKCS#7 signed data. Set the actual signed content so forge computes
    // the messageDigest attribute over it — this is what binds the signature to
    // the document. `detached: true` keeps the content out of the CMS blob while
    // still digesting it. (Passing the content via a messageDigest attribute
    // value does NOT work: forge overrides it with the digest of `p7.content`.)
    const p7 = forge.pkcs7.createSignedData()
    p7.content = forge.util.createBuffer(signedBytes.toString('binary'))

    p7.addCertificate(cert)
    p7.addSigner({
      key: privateKey,
      certificate: cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.signingTime, value: new Date().toISOString() },
        // messageDigest value is computed by forge over p7.content (above).
        { type: forge.pki.oids.messageDigest },
      ],
    })

    p7.sign({ detached: true })

    const asn1 = p7.toAsn1()
    const der = forge.asn1.toDer(asn1)
    return Buffer.from(der.getBytes(), 'binary')
  }
}

function formatPdfDate(date: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `D:${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}Z`
}
