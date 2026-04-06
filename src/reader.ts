/**
 * PDF Reader — Load, parse metadata, compute hash
 *
 * Pure functions, no side effects. Works in Node and browser.
 */

import { PDFDocument } from 'pdf-lib'
import { createHash } from 'node:crypto'

export interface PdfMetadata {
  /** Number of pages */
  pageCount: number
  /** PDF title (if set) */
  title: string | undefined
  /** PDF author (if set) */
  author: string | undefined
  /** PDF creation date */
  creationDate: Date | undefined
  /** PDF modification date */
  modificationDate: Date | undefined
  /** PDF producer (e.g., "pdf-lib") */
  producer: string | undefined
  /** File size in bytes */
  sizeBytes: number
  /** SHA-256 hash of the raw PDF bytes */
  sha256: string
}

export interface PdfLoadResult {
  /** Parsed PDF document (pdf-lib) */
  document: PDFDocument
  /** Raw bytes */
  bytes: Uint8Array
  /** Extracted metadata + hash */
  metadata: PdfMetadata
}

/**
 * Load a PDF from bytes, extract metadata, compute SHA-256.
 */
export async function loadPdf(input: Uint8Array | Buffer): Promise<PdfLoadResult> {
  const bytes = input instanceof Buffer ? new Uint8Array(input) : input

  const document = await PDFDocument.load(bytes, {
    ignoreEncryption: true,
    updateMetadata: false,
  })

  const sha256 = createHash('sha256').update(bytes).digest('hex')

  const metadata: PdfMetadata = {
    pageCount: document.getPageCount(),
    title: document.getTitle(),
    author: document.getAuthor(),
    creationDate: document.getCreationDate(),
    modificationDate: document.getModificationDate(),
    producer: document.getProducer(),
    sizeBytes: bytes.length,
    sha256,
  }

  return { document, bytes, metadata }
}

/**
 * Compute SHA-256 hash of raw PDF bytes.
 */
export function hashPdf(bytes: Uint8Array | Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}
