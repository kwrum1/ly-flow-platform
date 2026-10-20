<template>
  <section class="sx-page evidence-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">EVIDENCE OBJECT STORE</p>
        <h2 class="sx-title">证据库</h2>
        <p class="sx-subtitle">证据包与 PCAP 对象由 SeaweedFS 持久化；包内保留事件引用、对象哈希和创建者，下载走当前登录身份。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">刷新</button>
      </div>
    </header>

    <section class="evidence-stats">
      <article class="sx-metric"><span class="sx-metric-label"><i />证据包</span><strong class="sx-metric-value">{{ formatNumber(bundles.length) }}</strong><span class="sx-metric-note">当前可下载</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />总大小</span><strong class="sx-metric-value">{{ formatSize(totalSize) }}</strong><span class="sx-metric-note">内容寻址对象</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />最近生成</span><strong class="sx-metric-value date">{{ latestTime }}</strong><span class="sx-metric-note">按创建时间</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />本次上传</span><strong class="sx-metric-value success">{{ formatNumber(uploaded.length) }}</strong><span class="sx-metric-note">当前会话</span></article>
    </section>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <div class="evidence-tools">
      <section class="sx-panel">
        <div class="sx-panel-head"><div class="sx-panel-title">生成证据包</div><span class="sx-panel-meta">事件 + 对象引用</span></div>
        <div class="sx-panel-body evidence-form">
          <label><span>Incident ID</span><input v-model.trim="form.incident_id" class="sx-input" placeholder="inc-..." /></label>
          <label><span>Event UIDs</span><input v-model.trim="form.event_uids" class="sx-input" placeholder="逗号分隔，例如 evt-...,evt-..." /></label>
          <label><span>Artifact IDs</span><input v-model.trim="form.artifact_ids" class="sx-input" placeholder="可选，逗号分隔" /></label>
          <label><span>备注</span><input v-model.trim="form.note" class="sx-input" placeholder="取证背景 / 变更单号" /></label>
          <div class="form-actions">
            <span v-if="bundleMessage" class="response-message" :class="bundleMessageType">{{ bundleMessage }}</span>
            <button class="sx-btn primary" type="button" :disabled="creatingBundle || !canCreateBundle" @click="createBundle">{{ creatingBundle ? '打包中…' : '生成证据包' }}</button>
          </div>
        </div>
      </section>

      <section class="sx-panel">
        <div class="sx-panel-head"><div class="sx-panel-title">上传证据对象</div><span class="sx-panel-meta">PCAP / 二进制</span></div>
        <div class="sx-panel-body upload-form">
          <input ref="fileInput" class="file-input" type="file" @change="onFileChange" />
          <div class="upload-actions">
            <span class="sx-muted">{{ selectedFile ? `${selectedFile.name} · ${formatSize(selectedFile.size)}` : '选择本地 PCAP 或证据文件' }}</span>
            <button class="sx-btn primary" type="button" :disabled="uploading || !selectedFile" @click="uploadArtifact">{{ uploading ? '上传中…' : '上传到对象存储' }}</button>
          </div>
          <div v-if="uploadMessage" class="response-message" :class="uploadMessageType">{{ uploadMessage }}</div>
          <div v-if="uploaded.length" class="uploaded-list">
            <div v-for="artifact in uploaded" :key="artifact.id"><b class="sx-mono">{{ artifact.id }}</b><small>{{ artifact.name }} · {{ formatSize(artifact.size) }}</small></div>
          </div>
        </div>
      </section>
    </div>

    <section class="sx-panel">
      <div class="sx-panel-head"><div class="sx-panel-title">证据包列表</div><span class="sx-panel-meta">{{ bundles.length }} 个对象</span></div>
      <div class="sx-table-wrap sx-scroll">
        <table class="sx-table evidence-table">
          <thead><tr><th>证据包</th><th>Incident</th><th>大小</th><th>事件</th><th>对象</th><th>创建者</th><th>时间</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !bundles.length"><td colspan="8" class="sx-empty">正在读取证据包…</td></tr>
            <tr v-else-if="!bundles.length"><td colspan="8" class="sx-empty"><div><strong>还没有证据包</strong>在攻击链或上方表单中生成。</div></td></tr>
            <tr v-for="bundle in bundles" :key="bundle.id">
              <td><b class="sx-mono">{{ bundle.id }}</b><small class="hash">{{ bundle.sha256 }}</small></td>
              <td>{{ bundle.incident_id || '-' }}</td>
              <td>{{ formatSize(bundle.size) }}</td>
              <td>{{ bundle.event_uids?.length || 0 }}</td>
              <td>{{ bundle.artifact_ids?.length || 0 }}</td>
              <td>{{ bundle.created_by || '-' }}</td>
              <td><b>{{ formatTime(bundle.created_at) }}</b></td>
              <td><button class="sx-btn" type="button" @click="downloadBundle(bundle)">下载</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { evidenceClient } from '../api/domain'

const loading = ref(false)
const creatingBundle = ref(false)
const uploading = ref(false)
const error = ref('')
const bundleMessage = ref('')
const bundleMessageType = ref('success')
const uploadMessage = ref('')
const uploadMessageType = ref('success')
const bundles = ref([])
const uploaded = ref([])
const selectedFile = ref(null)
const fileInput = ref(null)
const form = reactive({ incident_id: '', event_uids: '', artifact_ids: '', note: '' })

const totalSize = computed(() => bundles.value.reduce((sum, item) => sum + Number(item.size || 0), 0))
const latestTime = computed(() => bundles.value.length ? formatShort(bundles.value[0].created_at) : '-')
const canCreateBundle = computed(() => form.event_uids.trim() || form.artifact_ids.trim())

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function formatSize(value) { const size = Number(value || 0); if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`; if (size >= 1024) return `${(size / 1024).toFixed(1)} KB`; return `${size} B` }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function formatShort(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) }
function splitIDs(value) { return String(value || '').split(',').map((item) => item.trim()).filter(Boolean) }

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = unwrap(await evidenceClient.bundles({ limit: 500 }))
    bundles.value = Array.isArray(data.items) ? data.items : []
  } catch (cause) {
    error.value = cause?.message || '证据包加载失败。'
  } finally {
    loading.value = false
  }
}

async function createBundle() {
  if (!canCreateBundle.value) return
  creatingBundle.value = true
  bundleMessage.value = ''
  try {
    const result = unwrap(await evidenceClient.createBundle({
      incident_id: form.incident_id || undefined,
      event_uids: splitIDs(form.event_uids),
      artifact_ids: splitIDs(form.artifact_ids),
      note: form.note || undefined,
    }))
    bundleMessage.value = `已生成 ${result.id || '证据包'}`
    bundleMessageType.value = 'success'
    form.event_uids = ''
    form.artifact_ids = ''
    form.note = ''
    await load()
  } catch (cause) {
    bundleMessage.value = cause?.message || '证据包生成失败：事件或对象必须存在。'
    bundleMessageType.value = 'error'
  } finally {
    creatingBundle.value = false
  }
}

function onFileChange(event) {
  selectedFile.value = event.target.files?.[0] || null
}

async function uploadArtifact() {
  if (!selectedFile.value) return
  uploading.value = true
  uploadMessage.value = ''
  try {
    const buffer = await selectedFile.value.arrayBuffer()
    const artifact = unwrap(await evidenceClient.uploadArtifact(buffer, {
      'Content-Type': selectedFile.value.type || 'application/octet-stream',
      'X-Lyflow-Artifact-Name': selectedFile.value.name,
    }))
    uploaded.value = [artifact, ...uploaded.value]
    uploadMessage.value = `已上传 ${artifact.id}`
    uploadMessageType.value = 'success'
    selectedFile.value = null
    if (fileInput.value) fileInput.value.value = ''
  } catch (cause) {
    uploadMessage.value = cause?.message || '证据对象上传失败。'
    uploadMessageType.value = 'error'
  } finally {
    uploading.value = false
  }
}

async function downloadBundle(bundle) {
  try {
    const token = localStorage.getItem('token') || ''
    const response = await fetch(`/api/v1/evidence/bundles/${encodeURIComponent(bundle.id)}/download`, { headers: { Authorization: `Bearer ${token}` } })
    if (!response.ok) throw new Error(`下载失败 (${response.status})`)
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${bundle.id}.json`
    link.click()
    URL.revokeObjectURL(url)
  } catch (cause) {
    error.value = cause?.message || '证据包下载失败。'
  }
}

onMounted(load)
</script>

<style scoped>
.evidence-page { gap: 14px; }
.evidence-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.sx-metric-value.date { color: var(--sx-text); font-size: 20px; }
.evidence-tools { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.evidence-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.evidence-form label { display: grid; gap: 4px; }
.evidence-form label > span { color: var(--sx-text-3); font-size: 9px; }
.evidence-form .form-actions { display: flex; grid-column: span 2; align-items: center; justify-content: flex-end; gap: 10px; }
.upload-form { display: grid; gap: 9px; }
.file-input { width: 100%; color: var(--sx-text-2); font-size: 10px; }
.upload-actions { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.uploaded-list { display: grid; gap: 4px; }
.uploaded-list > div { padding: 6px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.uploaded-list b { display: block; color: var(--sx-text); font-size: 9px; }
.uploaded-list small { color: var(--sx-text-3); font-size: 9px; }
.response-message { font-size: 10px; }
.response-message.success { color: var(--sx-success); }
.response-message.error { color: var(--sx-danger); }
.evidence-table { min-width: 1040px; }
.evidence-table .hash { display: block; max-width: 240px; overflow: hidden; color: var(--sx-text-3); font-family: var(--sx-font-mono); font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
@media (max-width: 1000px) {
  .evidence-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .evidence-tools { grid-template-columns: 1fr; }
}
@media (max-width: 600px) {
  .evidence-stats, .evidence-form { grid-template-columns: 1fr; }
  .evidence-form .form-actions { grid-column: auto; }
}
</style>
