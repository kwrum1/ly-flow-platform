<template>
  <section class="install-page">
    <header><h2>安装配置</h2></header>
    <div class="install-grid">
      <article class="install-card linux-card">
        <div class="card-head"><div><b>Linux Agent</b><span>x86_64 / ARM64 · Ubuntu 22.04+ / Debian 12+ / 现代 Linux</span></div><span class="ready">可用</span></div>
        <div class="token-row">
          <button type="button" class="token-button" :disabled="tokenLoading" @click="generateInstallToken">{{ tokenLoading ? '生成中' : '生成一次性安装令牌' }}</button>
          <span v-if="enrollmentToken" class="token-ok">已生成，10 分钟内有效</span>
          <span v-else class="token-hint">安装前需先生成令牌</span>
        </div>
        <div v-if="tokenError" class="token-error">{{ tokenError }}</div>
        <label>一键安装</label>
        <div class="command-box"><code>{{ installCommand }}</code></div>
        <div class="command-row"><div><label>运行状态</label><code>{{ statusCommand }}</code></div><div><label>运行日志</label><code>{{ logCommand }}</code></div></div>
        <label>卸载命令</label>
        <div class="command-box compact"><code>{{ uninstallCommand }}</code></div>
      </article>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import api from '../api'

const origin = typeof window === 'undefined' ? '' : window.location.origin
const enrollmentToken = ref('')
const tokenLoading = ref(false)
const tokenError = ref('')
const installUrl = computed(() => `${origin}/api/v1/agent/install.sh${enrollmentToken.value ? `?enrollment_token=${encodeURIComponent(enrollmentToken.value)}` : ''}`)
const uninstallUrl = computed(() => `${origin}/api/v1/agent/uninstall.sh`)
const installCommand = computed(() => `bash -c "if command -v curl; then curl -kfsSL ${installUrl.value} | bash; else wget --no-check-certificate -qO- ${installUrl.value} | bash; fi"`)
const uninstallCommand = computed(() => `bash -c "if command -v curl; then curl -kfsSL ${uninstallUrl.value} | bash; else wget --no-check-certificate -qO- ${uninstallUrl.value} | bash; fi"`)
const statusCommand = 'systemctl status ly-agent --no-pager'
const logCommand = 'journalctl -u ly-agent -n 80 --no-pager'

async function generateInstallToken() {
  tokenLoading.value = true
  tokenError.value = ''
  try {
    const response = await api.post('/agent/identity', {
      action: 'issue_enrollment',
      agent_id: `install-${Date.now()}`,
      ttl_minutes: 10,
    })
    enrollmentToken.value = response?.enrollment_token || response?.data?.enrollment_token || ''
    if (!enrollmentToken.value) tokenError.value = '服务端未返回安装令牌'
  } catch (error) {
    tokenError.value = error?.message || '生成安装令牌失败'
  } finally {
    tokenLoading.value = false
  }
}
</script>

<style scoped>
.install-page { display: grid; gap: 14px; min-width: 0; }
.install-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.install-card, .linux-card { border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 4%), transparent 34%), var(--lyf-surface); overflow: hidden; }
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); background: var(--lyf-surface-2); color: var(--lyf-ink); font-size: 13px; font-weight: 650; }
.ready { display: inline-flex; align-items: center; gap: 5px; color: var(--lyf-success); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 600; }
.command-box { display: grid; gap: 10px; padding: 14px 16px; }
.command-row { display: grid; gap: 4px; }
.command-row label { color: var(--lyf-ink-3); font-size: 10.5px; }
.command-row code { display: block; padding: 9px 11px; overflow-x: auto; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius-sm); background: var(--lyf-paper); color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 11px; line-height: 1.6; white-space: pre; }
.token-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 14px 16px; }
.token-button { height: 32px; padding: 0 12px; border: 1px solid var(--lyf-accent); border-radius: var(--lyf-radius-sm); background: var(--lyf-accent); color: #031018; font: inherit; font-size: 12px; font-weight: 650; cursor: pointer; }
.token-hint { color: var(--lyf-ink-3); font-size: 10.5px; }
.token-ok { color: var(--lyf-success); font-family: var(--lyf-font-data); font-size: 11px; }
.token-error { color: var(--lyf-critical); font-family: var(--lyf-font-data); font-size: 11px; }
.compact { font-size: 11px; }

@media (max-width: 1000px) { .install-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
