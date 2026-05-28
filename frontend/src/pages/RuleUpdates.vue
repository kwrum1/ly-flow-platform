<template>
  <section class="updates-page">
    <article class="panel source-panel">
      <div class="panel-title"><strong>规则平台更新</strong><span>开源规则源 · 一键下载编译热重载</span></div>
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
          <div v-else class="update-line muted">{{ sourceHintText(item) }}</div>
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
  const now = new Date()
  const diff = now - d
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`
  return d.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' }) + ' ' + d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
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
    const syncData = await ruleClient.platformSync({ source_id: item.source_id })
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
.updates-page{height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:#172033;box-sizing:border-box}.panel{border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:24px;box-shadow:0 24px 80px rgba(49,65,88,.14),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.source-panel{min-height:0;display:grid;grid-template-rows:44px auto minmax(0,1fr) auto;overflow:hidden}.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.38);background:rgba(255,255,255,.2)}.panel-title strong{font-size:14px}.panel-title span{color:#687789;font-size:12px}.bundle-bar{display:flex;align-items:center;gap:10px;justify-content:space-between;padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.34);background:rgba(15,23,42,.04)}.bundle-bar div{display:grid;gap:2px}.bundle-bar b{font-size:12px}.bundle-bar span{font-size:11px;color:#64748b}.source-grid{min-height:0;overflow:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));grid-auto-rows:minmax(145px,1fr);gap:10px;padding:12px}.source-card{display:grid;grid-template-rows:auto auto auto auto auto;gap:8px;padding:12px;border:1px solid rgba(255,255,255,.5);border-radius:18px;background:rgba(255,255,255,.36);min-height:0}.source-top,.meta{display:flex;justify-content:space-between;gap:8px;align-items:center}.source-top b{font-size:13px}.source-top span,.meta span{border:1px solid rgba(255,255,255,.55);border-radius:999px;padding:3px 8px;font-size:11px;color:#475569}small{font-size:11px;color:#667589;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.update-line{border-radius:12px;padding:8px 10px;font-size:12px;line-height:1.4}.update-line.muted{background:rgba(100,116,139,.08);color:#64748b;font-style:italic}.update-line.ok{background:rgba(34,197,94,.16);color:#15803d;font-weight:600}.update-line.error{background:rgba(239,68,68,.16);color:#991b1b;font-weight:600}.card-error{border-color:rgba(239,68,68,.42);box-shadow:0 0 0 1px rgba(239,68,68,.18)}.card-ok{border-color:rgba(34,197,94,.38);box-shadow:0 0 0 1px rgba(34,197,94,.14)}.primary,.ghost{height:30px;padding:0 12px;border:0;border-radius:12px;font-weight:900;cursor:pointer;font-size:12px;width:fit-content}.primary{background:linear-gradient(135deg,rgba(14,165,233,.88),rgba(52,211,153,.86));color:white}.ghost{border:1px solid rgba(15,23,42,.12);background:rgba(255,255,255,.42);color:#334155}.ghost.danger{color:#991b1b}.primary:disabled,.ghost:disabled{opacity:.5;cursor:not-allowed}.notice.error{padding:10px 12px;border-radius:14px}.version-strip{display:flex;gap:8px;overflow:auto;padding:8px 12px;border-top:1px solid rgba(255,255,255,.34)}.version-strip span{flex:0 0 auto;border-radius:999px;background:rgba(255,255,255,.42);border:1px solid rgba(255,255,255,.5);font-size:11px;color:#526174;padding:5px 9px}@media(max-width:720px){.source-grid{grid-template-columns:1fr}.bundle-bar{align-items:flex-start;flex-direction:column}.panel-title{align-items:flex-start;height:auto;min-height:44px;flex-direction:column;padding:10px 16px}}
</style>
