<template>
  <main class="ly-auth-page">
    <section class="ly-auth-brand">
      <div class="ly-auth-brand-copy">
        <XdrLogo class="ly-auth-mark" :size="64" inverse />
        <p>LYFLOW SECURITY</p>
        <h1>流影安全态势感知平台</h1>
        <p class="ly-auth-lede">网络、主机与应用三侧证据统一关联，把告警变成可追溯、可闭环的处置链。</p>
        <div class="ly-auth-capabilities" aria-label="平台能力">
          <span>流量检测</span>
          <span>终端防护</span>
          <span>XDR 关联</span>
          <span>ATT&amp;CK</span>
        </div>
      </div>
      <div class="ly-auth-status"><i />安全运营控制台 · 在线</div>
    </section>

    <section class="ly-auth-form-area">
      <div class="ly-auth-form-box" aria-label="登录表单">
        <header class="ly-auth-header">
          <p>SECURE ACCESS</p>
          <h2>管理员登录</h2>
          <span>请输入管理账号进入控制台</span>
        </header>

        <form class="ly-auth-form" @submit.prevent="handleLogin">
          <label>
            <span>账号</span>
            <input v-model.trim="form.username" type="text" placeholder="管理员账号" autocomplete="username" spellcheck="false">
          </label>
          <label>
            <span>密码</span>
            <input v-model="form.password" type="password" placeholder="登录密码" autocomplete="current-password">
          </label>
          <div v-if="error" class="ly-auth-error">{{ error }}</div>
          <button type="submit" :disabled="loading">
            <span v-if="!loading">进入控制台</span>
            <span v-else class="ly-auth-spinner" />
          </button>
        </form>

        <footer class="ly-auth-foot">
          <span>会话凭据仅保存在本机</span>
          <span class="ly-auth-foot-mark">v1.0.0 · XDR · RASP · YARA</span>
        </footer>
      </div>
    </section>
  </main>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import XdrLogo from '../components/XdrLogo.vue'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const form = ref({ username: '', password: '' })
const loading = ref(false)
const error = ref('')

const handleLogin = async () => {
  if (!form.value.username || !form.value.password) {
    error.value = '请输入账号和密码'
    return
  }
  loading.value = true
  error.value = ''
  try {
    await authStore.login({ username: form.value.username, password: form.value.password })
    router.push(authStore.needsPasswordChange ? '/change-password' : '/dashboard')
  } catch (e) {
    error.value = e?.message || '登录失败，请检查凭据'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.ly-auth-page {
  box-sizing: border-box;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 440px;
  width: 100%;
  min-height: 100vh;
  align-items: center;
  gap: clamp(32px, 6vw, 88px);
  padding: 48px clamp(24px, 7vw, 96px);
  background:
    radial-gradient(80% 70% at 8% 6%, var(--v-accent-soft), transparent 60%),
    var(--v-canvas);
  color: var(--v-ink);
}

.ly-auth-page * { box-sizing: border-box; }

.ly-auth-brand { position: relative; min-height: 480px; display: flex; align-items: center; }
.ly-auth-brand-copy { max-width: 620px; }

.ly-auth-mark {
  margin-bottom: 22px;
  padding: 10px;
  border-radius: var(--v-radius);
  background: var(--v-accent);
  color: #fff;
}

.ly-auth-brand-copy > p:first-of-type {
  margin: 0 0 12px;
  color: var(--v-accent);
  font-family: var(--v-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.22em;
}

.ly-auth-brand-copy h1 {
  margin: 0;
  color: var(--v-ink);
  font-size: clamp(30px, 3.4vw, 44px);
  font-weight: 650;
  letter-spacing: -0.03em;
  line-height: 1.14;
}

.ly-auth-lede { max-width: 520px; margin: 18px 0 26px; color: var(--v-ink-3); font-size: 13px; line-height: 1.8; }

.ly-auth-capabilities { display: flex; flex-wrap: wrap; gap: 8px; }
.ly-auth-capabilities span {
  padding: 5px 11px;
  border: 1px solid var(--v-line);
  border-radius: 999px;
  background: var(--v-surface);
  color: var(--v-ink-2);
  font-size: 11px;
}

.ly-auth-status { position: absolute; left: 0; bottom: 0; display: inline-flex; align-items: center; gap: 8px; color: var(--v-ink-3); font-size: 11px; }
.ly-auth-status i { width: 6px; height: 6px; border-radius: 50%; background: var(--v-success); }

.ly-auth-form-area { position: relative; }
.ly-auth-form-box {
  padding: 30px 28px 22px;
  border: 1px solid var(--v-line);
  border-radius: var(--v-radius-lg);
  background: var(--v-surface);
  box-shadow: var(--v-shadow-lg);
}

.ly-auth-header p { margin: 0 0 8px; color: var(--v-accent); font-family: var(--v-mono); font-size: 10px; font-weight: 600; letter-spacing: 0.2em; }
.ly-auth-header h2 { margin: 0; color: var(--v-ink); font-size: 21px; font-weight: 650; letter-spacing: -0.02em; }
.ly-auth-header span { display: block; margin-top: 6px; color: var(--v-ink-3); font-size: 11.5px; }

.ly-auth-form { display: grid; gap: 14px; margin-top: 24px; }
.ly-auth-form label { display: grid; gap: 6px; }
.ly-auth-form label > span { color: var(--v-ink-3); font-size: 11.5px; font-weight: 500; }
.ly-auth-form input {
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--v-line-2);
  border-radius: var(--v-radius-sm);
  background: var(--v-surface);
  color: var(--v-ink);
  font: inherit;
  font-size: 13px;
  outline: 0;
  transition: border-color var(--v-motion), box-shadow var(--v-motion);
}
.ly-auth-form input::placeholder { color: var(--v-ink-4); }
.ly-auth-form input:focus { border-color: var(--v-accent); box-shadow: 0 0 0 3px var(--v-accent-soft); }

.ly-auth-form button {
  height: 42px;
  margin-top: 4px;
  border: 1px solid var(--v-accent);
  border-radius: var(--v-radius-sm);
  background: var(--v-accent);
  color: #fff;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: background var(--v-motion);
}
.ly-auth-form button:hover:not(:disabled) { background: var(--v-accent-2); }
.ly-auth-form button:disabled { opacity: 0.6; cursor: not-allowed; }

.ly-auth-error { padding: 8px 10px; border: 1px solid var(--v-critical-line); border-left-width: 3px; border-radius: var(--v-radius-sm); background: var(--v-critical-soft); color: var(--v-critical); font-size: 12px; }

.ly-auth-spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgb(255 255 255 / 40%); border-top-color: #fff; border-radius: 50%; animation: ly-auth-spin 0.8s linear infinite; }

.ly-auth-foot { display: flex; justify-content: space-between; gap: 12px; margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--v-line); color: var(--v-ink-4); font-size: 10px; }
.ly-auth-foot-mark { font-family: var(--v-mono); letter-spacing: 0.1em; }

@keyframes ly-auth-spin { to { transform: rotate(360deg); } }

@media (max-width: 900px) {
  .ly-auth-page { grid-template-columns: minmax(0, 1fr); padding: 32px 20px; align-content: center; }
  .ly-auth-brand { min-height: 0; }
  .ly-auth-status { position: static; margin-top: 18px; }
  .ly-auth-form-box { padding: 22px 18px 16px; }
}

@media (prefers-reduced-motion: reduce) {
  .ly-auth-spinner { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; }
}
</style>
