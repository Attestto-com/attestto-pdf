import { describe, it, expect } from 'vitest'
import { loadPdf, hashPdf } from '../src/reader.js'
import { PDFDocument } from 'pdf-lib'

async function createTestPdf(): Promise<Uint8Array> {
  const doc = PDFDocument.create()
  const page = (await doc).addPage([612, 792])
  page.drawText('Attestto PDF Test Document', { x: 50, y: 700, size: 18 })
  page.drawText('This is a test PDF for unit testing.', { x: 50, y: 670, size: 12 })
  return (await doc).save()
}

describe('reader', () => {
  it('loads a PDF and extracts metadata', async () => {
    const pdfBytes = await createTestPdf()
    const result = await loadPdf(pdfBytes)

    expect(result.metadata.pageCount).toBe(1)
    expect(result.metadata.sizeBytes).toBeGreaterThan(0)
    expect(result.metadata.sha256).toMatch(/^[a-f0-9]{64}$/)
    expect(result.document).toBeDefined()
    expect(result.bytes).toBeInstanceOf(Uint8Array)
  })

  it('accepts Buffer input', async () => {
    const pdfBytes = await createTestPdf()
    const buffer = Buffer.from(pdfBytes)
    const result = await loadPdf(buffer)

    expect(result.metadata.pageCount).toBe(1)
  })

  it('sha256 is consistent', async () => {
    const pdfBytes = await createTestPdf()
    const r1 = await loadPdf(pdfBytes)
    const r2 = await loadPdf(pdfBytes)

    expect(r1.metadata.sha256).toBe(r2.metadata.sha256)
  })

  it('different PDFs produce different hashes', async () => {
    const pdf1 = await createTestPdf()

    const doc2 = await PDFDocument.create()
    const page2 = doc2.addPage()
    page2.drawText('Different content', { x: 50, y: 700 })
    const pdf2 = await doc2.save()

    const h1 = hashPdf(pdf1)
    const h2 = hashPdf(pdf2)

    expect(h1).not.toBe(h2)
  })

  it('hashPdf matches loadPdf sha256', async () => {
    const pdfBytes = await createTestPdf()
    const result = await loadPdf(pdfBytes)
    const hash = hashPdf(pdfBytes)

    expect(hash).toBe(result.metadata.sha256)
  })
})
