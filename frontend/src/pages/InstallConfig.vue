<template>
  <section class="install-page">
    <header class="install-header">
      <h2>安装配置</h2>
    </header>

    <section class="guide-card">
      <div class="guide-title">
        <strong>客户端安装指引</strong>
        <span>Linux 自动识别架构一键安装 / Windows 手动下载安装</span>
      </div>

      <div class="step-row">
        <div class="step-index">1</div>
        <div class="step-main">
          <h3>Linux：复制一键安装命令</h3>
          <p>脚本会自动判断 x86_64 / arm64 架构并下载对应 Linux Agent；x86 与 ARM 主机使用同一条命令，Linux 版本保留 AF_PACKET 与 PF_RING 策略。</p>
          <div class="command-box">
            <code>{{ installCommand }}</code>
          </div>
        </div>
      </div>

      <div class="step-row">
        <div class="step-index">2</div>
        <div class="step-main">
          <h3>在目标主机上以管理员权限执行安装命令</h3>
          <p>Linux 系统的管理员一般是 root 用户。请在需要接入流影的目标主机终端中执行上方命令。</p>
        </div>
      </div>

      <div class="step-row">
        <div class="step-index">3</div>
        <div class="step-main">
          <h3>检查安装是否成功</h3>
          <p>执行下面命令，查看输出结果中是否显示 <b>Active: active (running)</b> 字样，如有则安装启动成功。</p>
          <div class="command-box small">
            <code>{{ statusCommand }}</code>
          </div>
          <div class="command-box small">
            <code>{{ logCommand }}</code>
          </div>
        </div>
      </div>

      <div class="step-row">
        <div class="step-index">4</div>
        <div class="step-main">
          <h3>需要下线主机时执行卸载命令</h3>
          <p>卸载会停止并移除 ly-agent 服务，清理默认安装目录。</p>
          <div class="command-box small">
            <code>{{ uninstallCommand }}</code>
          </div>
        </div>
      </div>

      <div class="step-row">
        <div class="step-index">5</div>
        <div class="step-main">
          <h3>Windows：下载单文件 Agent</h3>
          <p>Windows Agent 使用 Npcap/WinPcap 兼容 PCAP 抓包分析。下载后以管理员身份运行 exe，默认连接当前控制台；程序无前端界面，仅在右下角显示流影托盘图标。</p>
          <div class="download-actions">
            <a class="download-link" :href="windowsAmd64Url" download>下载 Windows x86_64 Agent</a>
          </div>
          <div class="command-box small">
            <code>{{ windowsDownloadUrl }}</code>
          </div>
          <div class="command-box small">
            <code>{{ windowsInstallNote }}</code>
          </div>
        </div>
      </div>
    </section>


  </section>
</template>

<script setup>
import { computed } from 'vue'

const origin = typeof window === 'undefined' ? '' : window.location.origin
const installUrl = computed(() => `${origin}/api/v1/agent/install.sh`)
const uninstallUrl = computed(() => `${origin}/api/v1/agent/uninstall.sh`)
const windowsAmd64Url = computed(() => `${origin}/api/v1/agent/download?os=windows&arch=amd64`)
const windowsDownloadUrl = computed(() => `Windows 下载地址：${windowsAmd64Url.value}`)
const installCommand = computed(() => `bash -c "if (command -v curl); then (curl -kfsSL ${installUrl.value} | bash); else (wget --no-check-certificate -q -O - ${installUrl.value} | bash); fi"`)
const uninstallCommand = computed(() => `bash -c "if (command -v curl); then (curl -kfsSL ${uninstallUrl.value} | bash); else (wget --no-check-certificate -q -O - ${uninstallUrl.value} | bash); fi"`)
const statusCommand = 'systemctl status ly-agent --no-pager'
const logCommand = 'journalctl -u ly-agent -n 80 --no-pager'
const windowsInstallNote = '先安装 Npcap，再右键 ly-agent-windows-amd64.exe 选择“以管理员身份运行”；Agent 无打开/退出菜单，停止请使用 Windows 服务或任务管理器。'
</script>

<style scoped>
.install-page{position:relative;height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:var(--text-primary);box-sizing:border-box}.install-header,.guide-card{border:1px solid var(--border-color);border-radius:var(--card-radius);background:var(--bg-card);box-shadow:var(--shadow-card)}.install-header{height:44px;display:flex;align-items:center;padding:0 16px}.install-header h2{margin:0;color:var(--text-primary);font-size:16px}.guide-card{min-height:0;overflow:auto}.guide-title{height:44px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 16px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.guide-title strong{color:var(--text-primary);font-size:14px}.guide-title span{color:var(--text-muted);font-size:12px}.step-row{display:grid;grid-template-columns:38px minmax(0,1fr);gap:14px;padding:16px 18px;border-bottom:1px solid var(--border-light)}.step-row:last-child{border-bottom:0}.step-index{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,var(--primary-color),var(--risk-low));color:var(--text-inverse);font-size:12px;font-weight:950;box-shadow:0 10px 28px rgba(56,189,248,.18)}.step-main h3{margin:0 0 8px;color:var(--text-primary);font-size:15px}.step-main p{margin:0 0 10px;color:var(--text-secondary);font-size:12px;line-height:1.7}.step-main b{color:var(--primary-light)}.command-box{padding:12px;border:1px solid var(--border-light);border-radius:var(--card-radius-sm);background:rgba(2,8,23,.24);margin-top:8px}.command-box code{white-space:pre-wrap;word-break:break-all;color:#bfe7ff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.55}.download-actions{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 10px}.download-link{display:inline-flex;align-items:center;justify-content:center;min-height:32px;padding:0 14px;border:1px solid rgba(56,189,248,.42);border-radius:999px;background:rgba(56,189,248,.12);color:#bfe7ff;font-size:12px;font-weight:800;text-decoration:none}.download-link.secondary{border-color:var(--border-light);background:rgba(148,163,184,.1);color:var(--text-secondary)}.download-link:hover{border-color:var(--primary-light);color:var(--primary-light)}@media(max-width:980px){.guide-title{height:auto;align-items:flex-start;flex-direction:column;padding:14px}.install-page{padding:10px}.step-row{grid-template-columns:1fr}}
</style>
