<template>
  <div class="intelligence-page">
    <div class="intel-tabs">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        :class="{ active: activeTab === tab.key }"
        @click="setActiveTab(tab.key)"
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
        >
          <path :d="tab.path" />
        </svg>
        <span>{{ tab.label }}</span>
      </button>
    </div>

    <div class="intel-content">
      <div
        v-if="activeTab === 'rasp-apps'"
        class="sub-page"
      >
        <RASP />
      </div>
      <div
        v-else-if="activeTab === 'runtime-hosts'"
        class="sub-page"
      >
        <RASP />
      </div>
      <div
        v-else-if="activeTab === 'combined'"
        class="sub-page"
      >
        <XDR />
      </div>
      <div
        v-else-if="activeTab === 'rules'"
        class="sub-page"
      >
        <Rules />
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import XDR from './XDR.vue'
import RASP from './RASP.vue'
import Rules from './Rules.vue'
import { THREAT_INTELLIGENCE_TABS } from '../../domain/contracts/api-contracts'

const route = useRoute()
const router = useRouter()

const tabs = [
  ...THREAT_INTELLIGENCE_TABS.map(tab => ({ ...tab, path: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' })),
  { key: 'rules', label: '规则管理', path: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2 14 8 20 8 M16 13H8 M16 17H8 M10 9H8' }
]

const activeTab = computed(() => {
  const tab = route.query.tab || route.path.split('/').pop()
  if (tab === 'xdr' || tab === 'dpi') return 'combined'
  if (tab === 'rasp') return 'rasp-apps'
  if (tab === 'runtime') return 'runtime-hosts'
  return tabs.some(item => item.key === tab) ? tab : 'rasp-apps'
})

const setActiveTab = (tab) => {
  if (tab === 'rules') {
    router.push('/intelligence/rules')
    return
  }
  router.push({ path: '/intelligence', query: { tab } })
}
</script>

<style scoped>
.intelligence-page { min-height: 100%; }
.intel-tabs { display: flex; gap: 12px; margin-bottom: 20px; }
.intel-tabs button { display: flex; align-items: center; gap: 8px; padding: 12px 20px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-secondary); font-size: 14px; cursor: pointer; transition: all var(--transition-fast); }
.intel-tabs button:hover { border-color: var(--primary-color); color: var(--text-primary); }
.intel-tabs button.active { background: linear-gradient(135deg, var(--primary-color), var(--primary-dark)); border-color: var(--primary-color); color: white; }
.intel-tabs button svg { width: 18px; height: 18px; }
.intel-content { min-height: 400px; }
.sub-page { animation: fadeIn 0.2s ease; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
</style>
