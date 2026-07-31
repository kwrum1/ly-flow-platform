<template>
  <section class="updates-page">
    <article class="panel source-panel">
      <div class="panel-title"><strong>规则平台更新</strong></div>
      <div class="bundle-bar">
        <div><b>当前生效 Bundle</b><span>{{ activeBundleText }}</span></div>
      </div>
      <div class="source-grid">
        <div v-for="item in visibleSources" :key="item.source_id" class="source-card" :class="{ 'card-error': !!syncErrors[item.source_id], 'card-ok': !!syncResults[item.source_id] }">
          <div class="source-top"><b>{{ item.vendor || item.name || item.source_id }}</b><span>{{ item.category?.toUpperCase() || item.license_policy || 'SOURCE' }}</span></div>
          <small>{{ item.url || item.name }}</small>
          <div class="meta">
            <span>类型 {{ item.source_type || '-' }}</span>
            <span>最近更新 {{ versionText(item) }}</span>
          </div>
          <div v-if="syncErrors[item.source_id]" class="update-line error">{{ syncErrors[item.source_id] }}</div>
          <div v-else-if="syncResults[item.source_id]" class="update-line ok">{{ syncResults[item.source_id] }}</div>
          <button class="primary small" :disabled="updating === item.source_id" @click="syncSource(item)">{{ updating === item.source_id ? '更新中…' : '更新' }}</button>
        </div>
      </div>
    </article>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ruleClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime, platformNow } from '../shared/time'

const sources = ref([])
const activeBundle = ref(null)
const loading = ref(false)
const updating = ref('')
const syncErrors = reactive({})
const syncResults = reactive({})

const visibleSources = computed(() => sources.value.filter(canUpdateSource))

const activeBundleText = computed(() => {
  const bundle = activeBundle.value || {}
  const count = Number.isFinite(Number(bundle.rule_count)) ? Number(bundle.rule_count) : Array.isArray(bundle.rules) ? bundle.rules.length : Number(bundle.total || 0)
  return `${bundle.version || bundle.bundle_id || '未激活'} · ${count} 条规则`
})

function shortTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (isNaN(d.getTime())) return String(value).slice(0, 10)
  const now = platformNow()
  const diff = now - d
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`
  return formatChinaDateTime(value)
}

async function loadSources() {
  loading.value = true
  try {
    const [sourceData, activeData] = await Promise.all([
      ruleClient.platformSources(),
      ruleClient.platformActiveBundle(),
    ])
    sources.value = normalizeItems(sourceData).items.map(normalizeSource)
    activeBundle.value = activeData || null
  } catch (err) {
    // keep previous data on refresh failure
  } finally {
    loading.value = false
  }
}

async function syncSource(item) {
  updating.value = item.source_id
  delete syncErrors[item.source_id]
  delete syncResults[item.source_id]
  try {
    const syncData = await ruleClient.platformSync({ source_id: item.source_id, version: pinnedSyncVersion() })
    const info = syncData || {}
    const converted = info.converted_count ?? info.rule_count ?? 0
    const inserted = info.inserted_count ?? 0
    const dups = (info.duplicate_count ?? 0) + ((info.dedup_report || []).length)
    const parts = [`已同步 ${converted} 条规则`]
    if (inserted > 0) parts.push(`新增 ${inserted} 条`)
    if (dups > 0) parts.push(`去重 ${dups} 条`)
    syncResults[item.source_id] = parts.join(' · ')
    // update item's version time locally
    item._last_sync = new Date().toISOString()
    // refresh active bundle
    activeBundle.value = await ruleClient.platformActivateBundle()
    // refresh source list in background (won't clear syncResults)
    loadSources()
  } catch (err) {
    syncErrors[item.source_id] = err?.code === 'API_TIMEOUT' || /超时|timeout/i.test(err?.message || '')
      ? '更新超时，后台仍在执行'
      : err?.message || '更新失败'
  } finally {
    updating.value = ''
  }
}

function versionText(item) {
  return shortTime(item._last_sync || item.last_sync || item.updated_at || '')
}

function pinnedSyncVersion() {
  return `sync-${new Date().toISOString().replace(/[-:.]/g, '').replace('Z', 'Z')}`
}

function sourceHintText(item) {
  return item.connector ? '点击更新下载最新规则' : '当前不可更新'
}

function normalizeSource(item) {
  const sourceId = item.source_id || item.id || ''
  return {
    ...item,
    source_id: sourceId,
    source_type: item.source_type || item.origin || (item.connector ? 'connector' : 'static'),
    vendor: item.vendor || item.name,
  }
}

function canUpdateSource(item) {
  if (!item?.source_id) return false
  if (!item.updatable || !item.connector || item.restricted) return false
  return !['lyflow-default', 'lyflow-compiled-local', 'openrasp-derived', 'custom-rasp-rules'].includes(item.source_id)
}

onMounted(loadSources)
</script>

<style scoped>
.updates-page{height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:#172033;box-sizing:border-box}.panel{border:1px solid #dce3ec;background:#fff;border-radius:6px;box-shadow:0 3px 12px rgba(44,66,96,.07)}.source-panel{min-height:0;display:grid;grid-template-rows:44px auto minmax(0,1fr);overflow:hidden}.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid #e3e9f1;background:#f7f9fc}.panel-title strong{font-size:14px}.bundle-bar{display:flex;align-items:center;gap:10px;justify-content:space-between;padding:10px 12px;border-bottom:1px solid #e3e9f1;background:#fff}.bundle-bar div{display:grid;gap:2px}.bundle-bar b{font-size:12px}.bundle-bar span{font-size:11px;color:#64748b}.source-grid{min-height:0;overflow:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));grid-auto-rows:minmax(145px,1fr);gap:10px;padding:12px}.source-card{display:grid;grid-template-rows:auto auto auto auto;gap:8px;padding:12px;border:1px solid #dce3ec;border-radius:6px;background:#fff;min-height:0}.source-top,.meta{display:flex;justify-content:space-between;gap:8px;align-items:center}.source-top b{font-size:13px}.source-top span,.meta span{border:0;border-radius:0;padding:0;font-size:11px;color:#475569}small{font-size:11px;color:#667589;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.update-line{border-radius:4px;padding:7px 9px;font-size:11px;line-height:1.4}.update-line.ok{background:#edf9f2;color:#15803d;font-weight:600}.update-line.error{background:#fff3f2;color:#991b1b;font-weight:600}.card-error{border-color:#f0b5b1}.card-ok{border-color:#a8d9c2}.primary,.ghost{height:30px;padding:0 12px;border:0;border-radius:4px;font-weight:800;cursor:pointer;font-size:12px;width:fit-content}.primary{background:#1976d2;color:#fff}.ghost{border:1px solid #d0d7e1;background:#fff;color:#334155}.ghost.danger{color:#991b1b}.primary:disabled,.ghost:disabled{opacity:.5;cursor:not-allowed}.notice.error{padding:10px 12px;border-radius:5px}.version-strip{display:flex;gap:8px;overflow:auto;padding:8px 12px;border-top:1px solid #e3e9f1}.version-strip span{flex:0 0 auto;border-radius:4px;background:#f3f7fc;border:1px solid #dce3ec;font-size:11px;color:#526174;padding:5px 9px}@media(max-width:720px){.source-grid{grid-template-columns:1fr}.bundle-bar{align-items:flex-start;flex-direction:column}.panel-title{align-items:flex-start;height:auto;min-height:44px;flex-direction:column;padding:10px 16px}}
</style>
