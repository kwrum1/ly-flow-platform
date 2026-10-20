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
*{box-sizing:border-box}.install-page{height:calc(100vh - 64px);min-height:680px;display:grid;grid-template-rows:42px minmax(0,1fr);gap:8px;padding:10px;background:#f3f6fa;color:#243149;overflow:hidden}.install-page>header{display:flex;align-items:center;padding:0 14px;border:1px solid #dce4ef;border-radius:6px;background:#fff}.install-page h2{margin:0;font-size:16px}.install-grid{min-height:0;display:grid;grid-template-columns:1fr 1fr;grid-template-rows:minmax(0,1fr);gap:8px}.install-card{min-height:0;padding:16px;border:1px solid #dce4ef;border-radius:6px;background:#fff;box-shadow:0 3px 12px rgba(44,66,96,.07)}.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid #e5ebf2}.card-head b,.card-head span{display:block}.card-head b{font-size:15px}.card-head div span{margin-top:4px;color:#778499;font-size:11px}.card-head .ready{padding:4px 8px;border:1px solid #b8dfca;border-radius:4px;background:#edf9f2;color:#19794b;font-size:11px}.install-card>label,.command-row label{display:block;margin:12px 0 6px;color:#65738a;font-size:11px}.command-box{padding:12px;border:1px solid #d9e2ed;border-radius:4px;background:#f6f8fb}.command-box code{color:#244466;font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.command-row{display:grid;grid-template-columns:1fr 1fr;gap:8px}.command-row>div{min-width:0}.command-row code{display:block;padding:9px;border:1px solid #d9e2ed;border-radius:4px;background:#f6f8fb;color:#244466;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.card-actions{display:flex;gap:8px;margin-top:16px}.card-actions a,.dependency-row>a{display:inline-flex;align-items:center;justify-content:center;height:34px;padding:0 13px;border:1px solid #1769d2;border-radius:4px;background:#1769d2;color:#fff;font-size:12px;font-weight:750;text-decoration:none}.card-actions a.secondary{border-color:#d6dfeb;background:#fff;color:#40506a}.dependency-row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:18px;padding:12px;border:1px solid #d9e2ed;border-radius:5px;background:#f7f9fc}.dependency-row b,.dependency-row span{display:block}.dependency-row b{font-size:12px}.dependency-row span{margin-top:4px;color:#788599;font-size:10px}.dependency-row>a{height:30px;white-space:nowrap}@media(max-width:900px){.install-page{height:auto;min-height:calc(100vh - 64px);overflow:auto}.install-grid{grid-template-columns:1fr;grid-template-rows:auto}.command-row{grid-template-columns:1fr}}
.token-row{display:flex;align-items:center;gap:10px;margin:8px 0 4px}.token-button{height:30px;padding:0 12px;border:1px solid #1769d2;border-radius:4px;background:#1769d2;color:#fff;font-size:12px;cursor:pointer}.token-button:disabled{opacity:.55;cursor:not-allowed}.token-ok{color:#19794b;font-size:12px}.token-hint{color:#8a96a8;font-size:12px}.token-error{margin:4px 0;color:#a72820;font-size:12px}
</style>
