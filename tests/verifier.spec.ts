import { describe, it, expect, beforeAll } from 'vitest'
import { verifyPdf, trimContentsPadding } from '../src/verifier.js'
import { signPdf, createP12Signer } from '../src/signer.js'
import type { SignOptions } from '../src/signer.js'
import { PDFDocument } from 'pdf-lib'
import forge from 'node-forge'

/** Generate a self-signed X.509 certificate + private key for testing. */
function generateTestCert(): {
  cert: forge.pki.Certificate
  privateKey: forge.pki.rsa.PrivateKey
  certPem: string
} {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '02'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1)

  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: 'Attestto Verifier Test' },
    { name: 'organizationName', value: 'Attestto Test Org' },
    { name: 'countryName', value: 'CR' },
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)

  cert.sign(keys.privateKey, forge.md.sha256.create())

  return {
    cert,
    privateKey: keys.privateKey,
    certPem: forge.pki.certificateToPem(cert),
  }
}

/** Generate a CA certificate and a leaf certificate signed by that CA. */
function generateCaAndLeaf(): { caPem: string; leafCertPem: string; leafSigner: (b: Buffer) => Promise<Buffer> } {
  const caKeys = forge.pki.rsa.generateKeyPair(2048)
  const ca = forge.pki.createCertificate()
  ca.publicKey = caKeys.publicKey
  ca.serialNumber = '01'
  ca.validity.notBefore = new Date()
  ca.validity.notAfter = new Date()
  ca.validity.notAfter.setFullYear(ca.validity.notAfter.getFullYear() + 5)
  const caAttrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: 'Attestto Test Root CA' },
    { name: 'countryName', value: 'CR' },
  ]
  ca.setSubject(caAttrs)
  ca.setIssuer(caAttrs)
  ca.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true },
  ])
  ca.sign(caKeys.privateKey, forge.md.sha256.create())

  const leafKeys = forge.pki.rsa.generateKeyPair(2048)
  const leaf = forge.pki.createCertificate()
  leaf.publicKey = leafKeys.publicKey
  leaf.serialNumber = '1001'
  leaf.validity.notBefore = new Date()
  leaf.validity.notAfter = new Date()
  leaf.validity.notAfter.setFullYear(leaf.validity.notAfter.getFullYear() + 1)
  leaf.setSubject([
    { name: 'commonName', value: 'Attestto Test Leaf Signer' },
    { name: 'countryName', value: 'CR' },
  ])
  leaf.setIssuer(caAttrs)
  leaf.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
  ])
  leaf.sign(caKeys.privateKey, forge.md.sha256.create())

  const leafP12 = createTestP12(leaf, leafKeys.privateKey, 'leafpw')
  return {
    caPem: forge.pki.certificateToPem(ca),
    leafCertPem: forge.pki.certificateToPem(leaf),
    leafSigner: createP12Signer(leafP12, 'leafpw'),
  }
}

/** Create a P12/PFX buffer from a certificate and private key. */
function createTestP12(
  cert: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  password: string
): Buffer {
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [cert], password)
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes()
  return Buffer.from(p12Der, 'binary')
}

/** Create a minimal test PDF. */
async function createTestPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create()
  const page = doc.addPage([612, 792])
  page.drawText('Attestto PDF Verifier Test', { x: 50, y: 700, size: 18 })
  return doc.save()
}

/** Sign a PDF with the test cert, returning signed bytes. */
async function signTestPdf(
  pdfBytes: Uint8Array,
  certPem: string,
  signHash: (hash: Buffer) => Promise<Buffer>,
  overrides?: Partial<SignOptions>
): Promise<Uint8Array> {
  const opts: SignOptions = {
    identity: { certificatePem: certPem },
    sign: signHash,
    ...overrides,
  }
  const result = await signPdf(pdfBytes, opts)
  return result.pdf
}

describe('verifier', () => {
  let certPem: string
  let signHash: (hash: Buffer) => Promise<Buffer>
  let pdfBytes: Uint8Array
  let signedPdf: Uint8Array

  beforeAll(async () => {
    const testCert = generateTestCert()
    certPem = testCert.certPem
    const p12Buffer = createTestP12(testCert.cert, testCert.privateKey, 'verify-test')
    signHash = createP12Signer(p12Buffer, 'verify-test')
    pdfBytes = await createTestPdf()
    signedPdf = await signTestPdf(pdfBytes, certPem, signHash)
  })

  describe('unsigned PDF', () => {
    it('returns 0 signatures for an unsigned PDF', async () => {
      const result = await verifyPdf(pdfBytes)

      expect(result.signatureCount).toBe(0)
      expect(result.signatures).toHaveLength(0)
      expect(result.valid).toBe(false)
      expect(result.errors).toHaveLength(0)
    })
  })

  describe('signed PDF — structure', () => {
    it('finds exactly 1 signature', async () => {
      const result = await verifyPdf(signedPdf)

      expect(result.signatureCount).toBe(1)
      expect(result.signatures).toHaveLength(1)
    })

    it('reports valid=true with correct ByteRange and valid cert', async () => {
      const result = await verifyPdf(signedPdf)

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
      expect(result.signatures[0].certValid).toBe(true)
      expect(result.signatures[0].integrityValid).toBe(true)
    })

    it('accepts Buffer input', async () => {
      const bufInput = Buffer.from(signedPdf)
      const result = await verifyPdf(bufInput)

      expect(result.signatureCount).toBe(1)
    })
  })

  describe('certificate info extraction', () => {
    it('extracts signer common name', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.signerName).toBe('Attestto Verifier Test')
    })

    it('extracts certificate serial number', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.certSerial).toBeDefined()
      expect(sig.certSerial.length).toBeGreaterThan(0)
    })

    it('extracts certificate issuer CN', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      // Self-signed: issuer === subject
      expect(sig.certIssuer).toBe('Attestto Verifier Test')
    })

    it('extracts certificate validity dates', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.certValidFrom).toBeInstanceOf(Date)
      expect(sig.certValidTo).toBeInstanceOf(Date)
      expect(sig.certValidTo.getTime()).toBeGreaterThan(sig.certValidFrom.getTime())
    })

    it('certValid is true for a non-expired cert', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.certValid).toBe(true)
    })

    it('signatureBytes is a non-empty Buffer', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.signatureBytes).toBeInstanceOf(Buffer)
      expect(sig.signatureBytes.length).toBeGreaterThan(0)
    })
  })

  describe('integrity checking', () => {
    it('integrityValid is true when ByteRange is populated', async () => {
      const result = await verifyPdf(signedPdf)
      const sig = result.signatures[0]

      expect(sig.integrityValid).toBe(true)
    })

    it('detects tampering when bytes within the ByteRange are modified after signing (SOC-18)', async () => {
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)
      const tampered = Buffer.from(freshSigned)

      // Flip a byte in the document body, well before the signature dictionary,
      // so it is covered by the first ByteRange segment. Same length → offsets
      // stay valid; only the signed content changes.
      const tamperPos = 30
      tampered[tamperPos] = tampered[tamperPos] ^ 0xff

      const result = await verifyPdf(tampered)

      // The signature structure is still found, but integrity must now fail.
      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].integrityValid).toBe(false)
      expect(result.valid).toBe(false)
    })

    it('detects tampering in the trailer region (second ByteRange segment)', async () => {
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)
      const tampered = Buffer.from(freshSigned)

      const eofPos = tampered.lastIndexOf(Buffer.from('%%EOF'))
      expect(eofPos).toBeGreaterThan(100)
      const tamperPos = eofPos - 20
      tampered[tamperPos] = tampered[tamperPos] ^ 0xff

      const result = await verifyPdf(tampered)
      expect(result.signatures[0].integrityValid).toBe(false)
      expect(result.valid).toBe(false)
    })

    it('rejects a signature whose PKCS#7 signature bytes have been altered', async () => {
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)
      const result = await verifyPdf(freshSigned)
      expect(result.signatures[0].integrityValid).toBe(true) // baseline

      // Corrupt a byte inside the signature Contents hex (the PKCS#7 blob).
      const tampered = Buffer.from(freshSigned)
      const contentsIdx = tampered.indexOf(Buffer.from('/Contents <'))
      const hexStart = contentsIdx + '/Contents <'.length
      // Flip a hex nibble a little way into the DER so the signature no longer verifies.
      tampered[hexStart + 40] = tampered[hexStart + 40] === 0x61 ? 0x62 : 0x61 // 'a' <-> 'b'

      const altered = await verifyPdf(tampered)
      if (altered.signatureCount === 1) {
        expect(altered.signatures[0].integrityValid).toBe(false)
        expect(altered.valid).toBe(false)
      }
    })
  })

  describe('ByteRange coverage (SOC-34)', () => {
    it('a well-formed signature covers the whole document', async () => {
      const result = await verifyPdf(signedPdf)
      expect(result.signatures[0].coversDocument).toBe(true)
      expect(result.valid).toBe(true)
    })

    it('rejects bytes appended after signing (incremental-update / append attack)', async () => {
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)

      // Append a forged incremental update after the signed revision. The
      // original signature's ByteRange no longer reaches EOF, so the appended
      // bytes are unsigned — the document must not be reported valid.
      const appended = Buffer.concat([
        Buffer.from(freshSigned),
        Buffer.from('\n% forged incremental update — not covered by the signature\n'),
      ])

      const result = await verifyPdf(appended)
      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].coversDocument).toBe(false)
      expect(result.valid).toBe(false)
    })

    it('appended bytes are flagged even though the CMS signature itself is intact', async () => {
      // The appended bytes are outside the ByteRange, so integrityValid may stay
      // true — coverage is the check that catches this class of attack.
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)
      const appended = Buffer.concat([Buffer.from(freshSigned), Buffer.from('EXTRA')])

      const result = await verifyPdf(appended)
      expect(result.signatures[0].integrityValid).toBe(true)
      expect(result.signatures[0].coversDocument).toBe(false)
      expect(result.valid).toBe(false)
    })
  })

  describe('revocation checking (SOC-38)', () => {
    it('reports revocationStatus "unknown" and stays valid when no checker is supplied', async () => {
      const result = await verifyPdf(signedPdf)
      expect(result.signatures[0].revocationStatus).toBe('unknown')
      expect(result.valid).toBe(true)
    })

    it('invalidates the document when the checker reports the cert is revoked', async () => {
      const result = await verifyPdf(signedPdf, {
        checkRevocation: async () => 'revoked' as const,
      })
      expect(result.signatures[0].revocationStatus).toBe('revoked')
      expect(result.signatures[0].integrityValid).toBe(true) // crypto still fine…
      expect(result.valid).toBe(false) // …but a revoked cert is not valid
    })

    it('stays valid when the checker reports the cert is good', async () => {
      const result = await verifyPdf(signedPdf, {
        checkRevocation: async () => 'good' as const,
      })
      expect(result.signatures[0].revocationStatus).toBe('good')
      expect(result.valid).toBe(true)
    })

    it('passes the signer serial and issuer to the checker', async () => {
      let seenSerial: string | undefined
      let seenIssuer: string | undefined
      await verifyPdf(signedPdf, {
        checkRevocation: async (q) => {
          seenSerial = q.serialNumber
          seenIssuer = q.issuerCN
          expect(q.signerCertPem).toContain('BEGIN CERTIFICATE')
          return 'good'
        },
      })
      expect(seenSerial).toBeDefined()
      expect(seenIssuer).toBe('Attestto Verifier Test')
    })

    it('treats a throwing checker as "unknown" and does not crash', async () => {
      const result = await verifyPdf(signedPdf, {
        checkRevocation: async () => {
          throw new Error('OCSP responder unreachable')
        },
      })
      expect(result.signatures[0].revocationStatus).toBe('unknown')
      expect(result.valid).toBe(true)
    })
  })

  describe('trust-chain validation (SOC-30)', () => {
    it('chainStatus is "unchecked" and stays valid when no trust anchors are supplied', async () => {
      const result = await verifyPdf(signedPdf)
      expect(result.signatures[0].chainStatus).toBe('unchecked')
      expect(result.valid).toBe(true)
    })

    it('marks the signature trusted when its certificate chains to a supplied anchor', async () => {
      // The test signer cert is self-signed, so it is its own trust anchor.
      const result = await verifyPdf(signedPdf, { trustAnchors: [certPem] })
      expect(result.signatures[0].chainStatus).toBe('trusted')
      expect(result.valid).toBe(true)
    })

    it('marks the signature untrusted and invalid when it does not chain to the anchor', async () => {
      const stranger = generateTestCert() // unrelated self-signed cert
      const result = await verifyPdf(signedPdf, { trustAnchors: [stranger.certPem] })
      expect(result.signatures[0].chainStatus).toBe('untrusted')
      expect(result.signatures[0].integrityValid).toBe(true) // crypto still fine…
      expect(result.valid).toBe(false) // …but the issuer is not trusted
    })

    it('validates a real CA -> leaf chain against the CA anchor', async () => {
      const { caPem, leafCertPem, leafSigner } = generateCaAndLeaf()
      const signed = await signTestPdf(pdfBytes, leafCertPem, leafSigner)

      const trusted = await verifyPdf(signed, { trustAnchors: [caPem] })
      expect(trusted.signatures[0].chainStatus).toBe('trusted')
      expect(trusted.valid).toBe(true)

      // Same signed PDF, wrong anchor → untrusted
      const untrusted = await verifyPdf(signed, { trustAnchors: [generateTestCert().certPem] })
      expect(untrusted.signatures[0].chainStatus).toBe('untrusted')
      expect(untrusted.valid).toBe(false)
    })
  })

  /**
   * These are deliberately deterministic. The defect they cover reached us as a
   * 1-in-8 flake across the whole suite, and a flaky control is not a control:
   * the next real regression gets re-run away as "the known flake". The
   * condition is "the CMS ends on a zero nibble", so it can just be stated.
   */
  describe('/Contents padding is cut by DER length, not by trailing zeros', () => {
    // 30 04 | 01 02 03 00  =  SEQUENCE, length 4, content ending in a zero byte.
    const derEndingInZero = '300401020300'
    const pad = (hex: string, window = 64) => hex.padEnd(window, '0')

    it('keeps a signature byte that happens to be zero', () => {
      const kept = trimContentsPadding(pad(derEndingInZero))
      expect(kept).toBe(derEndingInZero)
      // The old implementation, for contrast: it eats the final 0x00 and
      // returns 5 bytes where the header declares 6.
      expect(pad(derEndingInZero).replace(/0+$/, '')).toBe('3004010203')
    })

    it('never returns an odd number of hex characters', () => {
      // An odd length is the signature of the bug: half a byte was removed.
      for (const body of ['00', '0000', '1000', '0010']) {
        const der = `3002${body}`.slice(0, 4) + body
        expect(trimContentsPadding(pad(der)).length % 2).toBe(0)
      }
    })

    it('reads the long-form length used by a real 2048-bit RSA CMS', () => {
      // 30 82 01 F4 = SEQUENCE, long form, 2 length bytes, 500 content bytes.
      const content = '00'.repeat(500)
      const der = '308201f4' + content
      expect(trimContentsPadding(pad(der, 16384))).toBe(der)
    })

    it('falls back to the old trim when the header is unreadable', () => {
      // Not a valid DER header: nothing better is available, so it degrades
      // rather than throwing inside signature discovery.
      expect(trimContentsPadding('30ff' + '00'.repeat(4))).toBe('30ff')
    })
  })

  describe('expired certificate', () => {
    it('certValid is false for an already-expired cert', async () => {
      // Generate a cert that expired yesterday
      const keys = forge.pki.rsa.generateKeyPair(2048)
      const cert = forge.pki.createCertificate()
      cert.publicKey = keys.publicKey
      cert.serialNumber = '03'

      const yesterday = new Date()
      yesterday.setDate(yesterday.getDate() - 2)
      const justExpired = new Date()
      justExpired.setDate(justExpired.getDate() - 1)

      cert.validity.notBefore = yesterday
      cert.validity.notAfter = justExpired

      const attrs: forge.pki.CertificateField[] = [
        { name: 'commonName', value: 'Expired Cert Test' },
        { name: 'countryName', value: 'CR' },
      ]
      cert.setSubject(attrs)
      cert.setIssuer(attrs)
      cert.sign(keys.privateKey, forge.md.sha256.create())

      const expiredP12 = createTestP12(cert, keys.privateKey, 'expired')
      const expiredSigner = createP12Signer(expiredP12, 'expired')
      const expiredCertPem = forge.pki.certificateToPem(cert)

      const expiredSignedPdf = await signTestPdf(pdfBytes, expiredCertPem, expiredSigner)
      const result = await verifyPdf(expiredSignedPdf)

      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].certValid).toBe(false)
      // Overall valid should be false because cert is expired
      expect(result.valid).toBe(false)
    })
  })

  describe('roundtrip: sign then verify', () => {
    it('sign with reason/location, verify finds 1 signature with correct signer', async () => {
      const signed = await signTestPdf(pdfBytes, certPem, signHash, {
        reason: 'Roundtrip Test',
        location: 'Test Lab',
      })

      const result = await verifyPdf(signed)

      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].signerName).toBe('Attestto Verifier Test')
      expect(result.signatures[0].certValid).toBe(true)
      expect(result.valid).toBe(true)
    })

    it('sign a multi-page PDF and verify finds 1 signature', async () => {
      const doc = await PDFDocument.create()
      doc.addPage([612, 792])
      doc.addPage([612, 792])
      doc.addPage([612, 792])
      const multiPagePdf = await doc.save()

      const signed = await signTestPdf(multiPagePdf, certPem, signHash)
      const result = await verifyPdf(signed)

      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].certValid).toBe(true)
    })

    it('sign a larger PDF with text content and verify', async () => {
      const doc = await PDFDocument.create()
      const page = doc.addPage([612, 792])
      // Add substantial content
      for (let y = 750; y > 50; y -= 20) {
        page.drawText(`Line at y=${y} - Lorem ipsum dolor sit amet, consectetur adipiscing elit.`, {
          x: 50,
          y,
          size: 10,
        })
      }
      const bigPdf = await doc.save()

      const signed = await signTestPdf(bigPdf, certPem, signHash)
      const result = await verifyPdf(signed)

      expect(result.signatureCount).toBe(1)
      expect(result.signatures[0].certValid).toBe(true)
      expect(result.signatures[0].signerName).toBe('Attestto Verifier Test')
    })
  })
})
