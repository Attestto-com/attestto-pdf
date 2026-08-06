import { describe, it, expect, beforeAll } from 'vitest'
import { signPdf, createP12Signer } from '../src/signer.js'
import type { SignOptions } from '../src/signer.js'
import { PDFDocument } from 'pdf-lib'
import forge from 'node-forge'

/** Generate a self-signed X.509 certificate + private key for testing. */
function generateTestCert(): {
  cert: forge.pki.Certificate
  privateKey: forge.pki.rsa.PrivateKey
  certPem: string
  keyPem: string
} {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1)

  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: 'Attestto Test Signer' },
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
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
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

/** Create a minimal test PDF using pdf-lib. */
async function createTestPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create()
  const page = doc.addPage([612, 792])
  page.drawText('Attestto PDF Signer Test', { x: 50, y: 700, size: 18 })
  page.drawText('This document is used for signer unit tests.', { x: 50, y: 670, size: 12 })
  return doc.save()
}

/** Build SignOptions from a P12 signer callback and test cert PEM. */
function buildSignOptions(
  signHash: (hash: Buffer) => Promise<Buffer>,
  certPem: string,
  overrides?: Partial<SignOptions>
): SignOptions {
  return {
    identity: { certificatePem: certPem },
    sign: signHash,
    ...overrides,
  }
}

describe('signer', () => {
  let testCert: ReturnType<typeof generateTestCert>
  let p12Buffer: Buffer
  let signHash: (hash: Buffer) => Promise<Buffer>
  let pdfBytes: Uint8Array

  beforeAll(async () => {
    testCert = generateTestCert()
    p12Buffer = createTestP12(testCert.cert, testCert.privateKey, 'test-password')
    signHash = createP12Signer(p12Buffer, 'test-password')
    pdfBytes = await createTestPdf()
  })

  describe('createP12Signer', () => {
    it('returns a function when given valid P12 and password', () => {
      const signer = createP12Signer(p12Buffer, 'test-password')
      expect(typeof signer).toBe('function')
    })

    it('rejects an incorrect password', () => {
      expect(() => createP12Signer(p12Buffer, 'wrong-password')).toThrow()
    })

    it('rejects invalid P12 data', () => {
      const garbage = Buffer.from('not-a-p12-file')
      expect(() => createP12Signer(garbage, 'test-password')).toThrow()
    })

    it('produces a valid PKCS#7 DER buffer when called', async () => {
      const hash = Buffer.alloc(32, 0xab) // fake SHA-256
      const sig = await signHash(hash)

      expect(sig).toBeInstanceOf(Buffer)
      expect(sig.length).toBeGreaterThan(0)

      // Should be parseable as ASN.1 / PKCS#7
      const asn1 = forge.asn1.fromDer(sig.toString('binary'))
      expect(asn1).toBeDefined()
    })
  })

  describe('signPdf', () => {
    it('returns a signed PDF larger than the input', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)

      expect(result.pdf).toBeInstanceOf(Uint8Array)
      expect(result.pdf.length).toBeGreaterThan(pdfBytes.length)
    })

    it('returns a valid SHA-256 hex string', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)

      expect(result.sha256).toMatch(/^[a-f0-9]{64}$/)
    })

    it('embeds /adbe.pkcs7.detached SubFilter in the output', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('adbe.pkcs7.detached')
    })

    it('embeds the signer name from the certificate CN', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('Attestto Test Signer')
    })

    it('accepts Buffer input as well as Uint8Array', async () => {
      const bufferInput = Buffer.from(pdfBytes)
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(bufferInput, opts)

      expect(result.pdf).toBeInstanceOf(Uint8Array)
      expect(result.pdf.length).toBeGreaterThan(pdfBytes.length)
    })

    it('includes reason when provided', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem, {
        reason: 'Unit Test Signing',
      })
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('Unit Test Signing')
    })

    it('includes location when provided', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem, {
        location: 'San Jose, CR',
      })
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('San Jose, CR')
    })

    it('includes contactInfo when provided', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem, {
        contactInfo: 'test@attestto.com',
      })
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('test@attestto.com')
    })

    it('includes all optional metadata together', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem, {
        reason: 'Full Metadata Test',
        location: 'Heredia, CR',
        contactInfo: 'full-test@attestto.com',
      })
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('Full Metadata Test')
      expect(pdfStr).toContain('Heredia, CR')
      expect(pdfStr).toContain('full-test@attestto.com')
    })

    it('calls anchor callback and returns txId', async () => {
      const fakeTxId = '5KtPn1LGuxhFiwjxErkxTb3XwEixy5ELRJKsqCgurhXSzfnM'
      const anchorFn = async (docHash: string): Promise<string> => {
        expect(docHash).toMatch(/^[a-f0-9]{64}$/)
        return fakeTxId
      }

      const opts = buildSignOptions(signHash, testCert.certPem, {
        anchor: anchorFn,
      })
      const result = await signPdf(pdfBytes, opts)

      expect(result.anchorTxId).toBe(fakeTxId)
    })

    it('returns no anchorTxId when anchor callback is not provided', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)

      expect(result.anchorTxId).toBeUndefined()
    })

    it('produces different sha256 for different PDFs', async () => {
      const doc2 = await PDFDocument.create()
      doc2.addPage([612, 792])
      const pdf2 = await doc2.save()

      const opts = buildSignOptions(signHash, testCert.certPem)
      const r1 = await signPdf(pdfBytes, opts)
      const r2 = await signPdf(pdf2, opts)

      expect(r1.sha256).not.toBe(r2.sha256)
    })

    it('contains a /Contents hex string in the signed output', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      // The signed PDF must contain the /Contents tag with a hex-encoded signature
      expect(pdfStr).toMatch(/\/Contents\s*<[0-9a-fA-F]+>/)
    })

    it('embeds an AttesttoSignature field name', async () => {
      const opts = buildSignOptions(signHash, testCert.certPem)
      const result = await signPdf(pdfBytes, opts)
      const pdfStr = Buffer.from(result.pdf).toString('latin1')

      expect(pdfStr).toContain('AttesttoSignature')
    })
  })
})
