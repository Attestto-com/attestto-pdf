<script setup lang="ts">
import { computed } from 'vue'
import type { VerifyResult, SignatureInfo, PdfMetadata } from '../index.js'

export interface SignaturePanelProps {
  /** Result from verifyPdf() */
  verification: VerifyResult | null
  /** PDF metadata from loadPdf() */
  metadata: PdfMetadata | null
  /** Solana anchor transaction ID (if anchored) */
  anchorTxId?: string
  /** Whether signing is available */
  canSign?: boolean
}

const props = withDefaults(defineProps<SignaturePanelProps>(), {
  canSign: false,
})

const emit = defineEmits<{
  (e: 'sign'): void
  (e: 'verify-onchain'): void
  (e: 'export'): void
}>()

const hasSignatures = computed(() => (props.verification?.signatureCount ?? 0) > 0)

function formatDate(date: Date | undefined): string {
  if (!date) return '—'
  return new Intl.DateTimeFormat('default', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

function truncateHash(hash: string, len = 12): string {
  if (hash.length <= len * 2) return hash
  return `${hash.slice(0, len)}...${hash.slice(-len)}`
}
</script>

<template>
  <div class="att-sig-panel">
    <!-- Signatures section -->
    <div class="att-sig-panel__section">
      <div class="att-sig-panel__section-title">
        Signatures
        <span v-if="verification" class="att-sig-panel__badge" :class="verification.valid ? 'att-sig-panel__badge--valid' : 'att-sig-panel__badge--invalid'">
          {{ verification.valid ? 'Valid' : 'Issues' }}
        </span>
      </div>

      <!-- No signatures -->
      <div v-if="!hasSignatures" class="att-sig-panel__empty">
        No signatures found
      </div>

      <!-- Signature cards -->
      <div
        v-for="(sig, i) in verification?.signatures"
        :key="i"
        class="att-sig-card"
        :class="{
          'att-sig-card--valid': sig.integrityValid && sig.certValid,
          'att-sig-card--invalid': !sig.integrityValid || !sig.certValid,
        }"
      >
        <div class="att-sig-card__icon">
          {{ sig.integrityValid && sig.certValid ? '✓' : '✗' }}
        </div>
        <div class="att-sig-card__info">
          <div class="att-sig-card__name">{{ sig.signerName }}</div>
          <div class="att-sig-card__detail">{{ sig.certIssuer }}</div>
          <div class="att-sig-card__detail">
            Valid: {{ formatDate(sig.certValidFrom) }} — {{ formatDate(sig.certValidTo) }}
          </div>
          <div v-if="sig.reason" class="att-sig-card__detail">
            Reason: {{ sig.reason }}
          </div>
          <div v-if="!sig.certValid" class="att-sig-card__warning">
            Certificate expired
          </div>
          <div v-if="!sig.integrityValid" class="att-sig-card__warning">
            Document modified after signing
          </div>
        </div>
      </div>

      <!-- Errors -->
      <div v-for="(err, i) in verification?.errors" :key="'err-' + i" class="att-sig-panel__error">
        {{ err }}
      </div>
    </div>

    <!-- Document section -->
    <div v-if="metadata" class="att-sig-panel__section">
      <div class="att-sig-panel__section-title">Document</div>
      <div class="att-sig-panel__row">
        <span class="att-sig-panel__label">Pages</span>
        <span class="att-sig-panel__value">{{ metadata.pageCount }}</span>
      </div>
      <div class="att-sig-panel__row">
        <span class="att-sig-panel__label">Size</span>
        <span class="att-sig-panel__value">{{ formatBytes(metadata.sizeBytes) }}</span>
      </div>
      <div class="att-sig-panel__row">
        <span class="att-sig-panel__label">SHA-256</span>
        <span class="att-sig-panel__value att-sig-panel__mono" :title="metadata.sha256">
          {{ truncateHash(metadata.sha256) }}
        </span>
      </div>
      <div v-if="metadata.title" class="att-sig-panel__row">
        <span class="att-sig-panel__label">Title</span>
        <span class="att-sig-panel__value">{{ metadata.title }}</span>
      </div>
      <div v-if="metadata.author" class="att-sig-panel__row">
        <span class="att-sig-panel__label">Author</span>
        <span class="att-sig-panel__value">{{ metadata.author }}</span>
      </div>
      <div v-if="anchorTxId" class="att-sig-panel__row">
        <span class="att-sig-panel__label">Solana</span>
        <span class="att-sig-panel__value att-sig-panel__mono">
          {{ truncateHash(anchorTxId) }}
        </span>
      </div>
    </div>

    <!-- Actions -->
    <div class="att-sig-panel__actions">
      <button
        v-if="canSign"
        class="att-sig-panel__btn att-sig-panel__btn--primary"
        @click="emit('sign')"
      >
        Sign this PDF
      </button>
      <button
        v-if="anchorTxId"
        class="att-sig-panel__btn"
        @click="emit('verify-onchain')"
      >
        Verify on-chain
      </button>
      <button class="att-sig-panel__btn" @click="emit('export')">
        Export
      </button>
    </div>
  </div>
</template>

<style scoped>
.att-sig-panel {
  display: flex;
  flex-direction: column;
  gap: 1px;
  background: var(--att-pdf-border, rgba(255, 255, 255, 0.08));
  border-radius: var(--att-pdf-radius, 0.5rem);
  overflow: hidden;
  height: 100%;
}

.att-sig-panel__section {
  padding: 1.25rem;
  background: var(--att-pdf-bg, #1a1a2e);
}

.att-sig-panel__section-title {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--att-pdf-text-muted, rgba(255, 255, 255, 0.4));
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.att-sig-panel__badge {
  font-size: 0.625rem;
  padding: 0.125rem 0.375rem;
  border-radius: 1rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.att-sig-panel__badge--valid {
  background: rgba(74, 222, 128, 0.12);
  color: #4ade80;
}

.att-sig-panel__badge--invalid {
  background: rgba(251, 113, 133, 0.12);
  color: #fb7185;
}

.att-sig-panel__empty {
  color: var(--att-pdf-text-muted, rgba(255, 255, 255, 0.3));
  font-size: 0.8125rem;
  padding: 0.5rem 0;
}

/* Signature card */
.att-sig-card {
  display: flex;
  gap: 0.75rem;
  padding: 0.75rem;
  border: 1px solid var(--att-pdf-border, rgba(255, 255, 255, 0.08));
  border-radius: 0.5rem;
  margin-bottom: 0.5rem;
}

.att-sig-card--valid {
  border-color: rgba(74, 222, 128, 0.2);
}

.att-sig-card--invalid {
  border-color: rgba(251, 113, 133, 0.2);
}

.att-sig-card__icon {
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.875rem;
  flex-shrink: 0;
}

.att-sig-card--valid .att-sig-card__icon {
  background: rgba(74, 222, 128, 0.12);
  color: #4ade80;
}

.att-sig-card--invalid .att-sig-card__icon {
  background: rgba(251, 113, 133, 0.12);
  color: #fb7185;
}

.att-sig-card__name {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.9));
}

.att-sig-card__detail {
  font-size: 0.75rem;
  color: var(--att-pdf-text-muted, rgba(255, 255, 255, 0.4));
  margin-top: 0.125rem;
}

.att-sig-card__warning {
  font-size: 0.75rem;
  color: #fb7185;
  margin-top: 0.25rem;
}

/* Document metadata rows */
.att-sig-panel__row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  padding: 0.25rem 0;
  font-size: 0.8125rem;
}

.att-sig-panel__label {
  color: var(--att-pdf-text-muted, rgba(255, 255, 255, 0.4));
}

.att-sig-panel__value {
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.8));
  text-align: right;
}

.att-sig-panel__mono {
  font-family: var(--att-pdf-font-mono, 'JetBrains Mono', monospace);
  font-size: 0.75rem;
}

.att-sig-panel__error {
  font-size: 0.75rem;
  color: #fb7185;
  padding: 0.375rem 0;
}

/* Actions */
.att-sig-panel__actions {
  padding: 1.25rem;
  background: var(--att-pdf-bg, #1a1a2e);
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: auto;
}

.att-sig-panel__btn {
  width: 100%;
  padding: 0.625rem 1rem;
  border-radius: 0.375rem;
  font-size: 0.8125rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  border: 1px solid var(--att-pdf-border, rgba(255, 255, 255, 0.12));
  background: transparent;
  color: var(--att-pdf-text, rgba(255, 255, 255, 0.7));
}

.att-sig-panel__btn:hover {
  background: rgba(255, 255, 255, 0.05);
  border-color: rgba(255, 255, 255, 0.2);
}

.att-sig-panel__btn--primary {
  background: var(--att-pdf-accent, #15803d);
  border-color: var(--att-pdf-accent, #15803d);
  color: #ffffff;
}

.att-sig-panel__btn--primary:hover {
  background: var(--att-pdf-accent-hover, #16a34a);
}
</style>
