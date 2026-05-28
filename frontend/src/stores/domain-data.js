import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import {
  assetAgentClient,
  attackWorkbenchClient,
  overviewClient,
  ruleClient,
  signalClient,
} from '../api/domain'

function createResourceState() {
  return {
    loading: ref(false),
    error: ref(''),
    data: ref(null),
    loadedAt: ref(''),
  }
}

async function loadResource(resource, loader) {
  resource.loading.value = true
  resource.error.value = ''
  try {
    const data = await loader()
    resource.data.value = data
    resource.loadedAt.value = new Date().toISOString()
    return data
  } catch (error) {
    resource.data.value = null
    resource.error.value = error?.message || '接口请求失败'
    throw error
  } finally {
    resource.loading.value = false
  }
}

export const useDomainDataStore = defineStore('domain-data', () => {
  const overview = createResourceState()
  const attackStats = createResourceState()
  const attackEvents = createResourceState()
  const incidents = createResourceState()
  const timeline = createResourceState()
  const assets = createResourceState()
  const agents = createResourceState()
  const rules = createResourceState()
  const signals = createResourceState()

  const hasCriticalError = computed(() => [overview, attackStats, attackEvents, incidents, timeline]
    .some((resource) => Boolean(resource.error.value)))

  const loadOverview = () => loadResource(overview, async () => ({
    health: await overviewClient.health(),
    stats: await overviewClient.stats(),
  }))

  const loadAttackWorkbench = () => Promise.all([
    loadResource(attackStats, () => attackWorkbenchClient.stats()),
    loadResource(attackEvents, () => attackWorkbenchClient.events({ limit: 50 })),
    loadResource(incidents, () => attackWorkbenchClient.incidents({ limit: 50 })),
    loadResource(timeline, () => attackWorkbenchClient.timeline({ limit: 100 })),
  ])

  const loadAssetsAgents = () => Promise.all([
    loadResource(assets, () => assetAgentClient.assets({ limit: 50 })),
    loadResource(agents, () => assetAgentClient.agents({ limit: 50 })),
  ])

  const loadRules = () => loadResource(rules, async () => ({
    list: await ruleClient.list(),
    stats: await ruleClient.stats(),
    categories: await ruleClient.categories(),
  }))

  const loadSignals = () => loadResource(signals, async () => ({
    xdr: await signalClient.xdrStats(),
    rasp: await signalClient.raspStats(),
    trace: await signalClient.traceStats(),
  }))

  return {
    overview,
    attackStats,
    attackEvents,
    incidents,
    timeline,
    assets,
    agents,
    rules,
    signals,
    hasCriticalError,
    loadOverview,
    loadAttackWorkbench,
    loadAssetsAgents,
    loadRules,
    loadSignals,
  }
})
