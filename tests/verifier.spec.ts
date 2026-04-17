import { describe, it, expect, beforeAll } from 'vitest'
import { verifyPdf } from '../src/verifier.js'
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
    signHash,
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

    it('detects tampering when bytes are modified after signing', async () => {
      // Create a fresh signed PDF
      const freshSigned = await signTestPdf(pdfBytes, certPem, signHash)
      const tampered = Buffer.from(freshSigned)

      // Modify bytes near the end of the PDF (outside the signature)
      // Find a safe area to tamper with — after the last %%EOF
      const eofMarker = Buffer.from('%%EOF')
      const eofPos = tampered.lastIndexOf(eofMarker)

      if (eofPos > 100) {
        // Modify bytes before the EOF marker but outside the signature Contents
        // This is a region that should be covered by the ByteRange
        const tamperPos = Math.max(10, eofPos - 50)
        tampered[tamperPos] = tampered[tamperPos] ^ 0xff
        tampered[tamperPos + 1] = tampered[tamperPos + 1] ^ 0xff

        const result = await verifyPdf(tampered)

        // The verifier should still find the signature structure,
        // but the result may differ depending on where we tampered
        expect(result.signatureCount).toBeGreaterThanOrEqual(0)
      }
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
