<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'

export interface PdfViewerProps {
  /** PDF file bytes */
  bytes: Uint8Array | null
  /** Initial page number (1-based) */
  initialPage?: number
  /** Zoom level (1 = 100%) */
  zoom?: number
}

const props = withDefaults(defineProps<PdfViewerProps>(), {
  initialPage: 1,
  zoom: 1,
})

const emit = defineEmits<{
  (e: 'page-change', page: number): void
  (e: 'loaded', pageCount: number): void
  (e: 'error', error: Error): void
}>()

const canvasRef = ref<HTMLCanvasElement | null>(null)
const currentPage = ref(props.initialPage)
const pageCount = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

// pdfjs-dist loaded dynamically (heavy dep, only load when needed)
let pdfDoc: any = null
let pdfjsLib: any = null

async function loadPdfJs() {
  if (pdfjsLib) return pdfjsLib
  pdfjsLib = await import('pdfjs-dist')

  // Set worker — use bundled worker or CDN fallback
  if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.mjs`
  }

  return pdfjsLib
}

async function loadDocument() {
  if (!props.bytes) return

  loading.value = true
  error.value = null

  try {
    const lib = await loadPdfJs()
    const loadingTask = lib.getDocument({ data: props.bytes.slice() })
    pdfDoc = await loadingTask.promise
    pageCount.value = pdfDoc.numPages
    currentPage.value = Math.min(props.initialPage, pageCount.value)
    emit('loaded', pageCount.value)
    await renderPage()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load PDF'
    emit('error', err instanceof Error ? err : new Error(String(err)))
  } finally {
    loading.value = false
  }
}

async function renderPage() {
  if (!pdfDoc || !canvasRef.value) return

  const page = await pdfDoc.getPage(currentPage.value)
  const viewport = page.getViewport({ scale: props.zoom * 1.5 }) // 1.5x for sharpness

  const canvas = canvasRef.value
  const ctx = canvas.getContext('2d')
  if (!ctx) return

  canvas.width = viewport.width
  canvas.height = viewport.height

  await page.render({ canvasContext: ctx, viewport }).promise
}

function nextPage() {
  if (currentPage.value < pageCount.value) {
    currentPage.value++
    emit('page-change', currentPage.value)
    renderPage()
  }
}

function prevPage() {
  if (currentPage.value > 1) {
    currentPage.value--
    emit('page-change', currentPage.value)
    renderPage()
  }
}

function goToPage(page: number) {
  const p = Math.max(1, Math.min(page, pageCount.value))
  if (p !== currentPage.value) {
    currentPage.value = p
    emit('page-change', currentPage.value)
    renderPage()
  }
}

watch(() => props.bytes, loadDocument)
watch(() => props.zoom, renderPage)

onMounted(() => {
  if (props.bytes) loadDocument()
})

const canPrev = computed(() => currentPage.value > 1)
const canNext = computed(() => currentPage.value < pageCount.value)

defineExpose({ nextPage, prevPage, goToPage, currentPage, pageCount })
</script>

<template>
  <div class="att-pdf-viewer">
    <!-- Loading -->
    <div v-if="loading" class="att-pdf-viewer__loading">
      <div class="att-pdf-viewer__spinner" />
      <span>Loading PDF...</span>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="att-pdf-viewer__error">
      <span>{{ error }}</span>
    </div>

    <!-- No document -->
    <div v-else-if="!bytes" class="att-pdf-viewer__empty">
      <span>No document loaded</span>
    </div>

    <!-- Canvas -->
    <template v-else>
      <div class="att-pdf-viewer__canvas-wrap">
        <canvas ref="canvasRef" class="att-pdf-viewer__canvas" />
      </div>

      <!-- Navigation -->
      <div v-if="pageCount > 0" class="att-pdf-viewer__nav">
        <button
          class="att-pdf-viewer__nav-btn"
          :disabled="!canPrev"
          @click="prevPage"
        >
          &larr;
        </button>
        <span class="att-pdf-viewer__nav-info">
          {{ currentPage }} / {{ pageCount }}
        </span>
        <button
          class="att-pdf-viewer__nav-btn"
          :disabled="!canNext"
          @click="nextPage"
        >
          &rarr;
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.att-pdf-viewer {
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
  overflow: hidden;
  background: var(--att-pdf-bg, #1a1a2e);
  border-radius: var(--att-pdf-radius, 0.5rem);
}

.att-pdf-viewer__canvas-wrap {
  flex: 1;
  overflow: auto;
  display: flex;
  justify-content: center;
  padding: 1rem;
  width: 100%;
}

.att-pdf-viewer__canvas {
  max-width: 100%;
  height: auto;
  box-shadow: 0 2px 16px rgba(0, 0, 0, 0.3);
  border-radius: 2px;
}

.att-pdf-viewer__nav {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem 1rem;
  background: var(--att-pdf-nav-bg, rgba(255, 255, 255, 0.05));
  border-top: 1px solid var(--att-pdf-border, rgba(255, 255, 255, 0.08));
  width: 100%;
  justify-content: center;
}

.att-pdf-viewer__nav-btn {
  background: none;
  border: 1px solid var(--att-pdf-border, rgba(255, 255, 255, 0.15));
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.8));
  padding: 0.375rem 0.75rem;
  border-radius: 0.25rem;
  cursor: pointer;
  font-size: 1rem;
  transition: all 0.15s;
}

.att-pdf-viewer__nav-btn:hover:not(:disabled) {
  background: rgba(255, 255, 255, 0.08);
}

.att-pdf-viewer__nav-btn:disabled {
  opacity: 0.3;
  cursor: default;
}

.att-pdf-viewer__nav-info {
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.6));
  font-size: 0.875rem;
  font-variant-numeric: tabular-nums;
}

.att-pdf-viewer__loading,
.att-pdf-viewer__error,
.att-pdf-viewer__empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.4));
  font-size: 0.875rem;
}

.att-pdf-viewer__spinner {
  width: 2rem;
  height: 2rem;
  border: 2px solid var(--att-pdf-border, rgba(255, 255, 255, 0.1));
  border-top-color: var(--att-pdf-accent, #4ade80);
  border-radius: 50%;
  animation: att-spin 0.8s linear infinite;
}

@keyframes att-spin {
  to { transform: rotate(360deg); }
}
</style>
