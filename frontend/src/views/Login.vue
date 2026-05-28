<template>
  <main class="auth-page">
    <section class="brand-panel">
      <p class="eyebrow">LYFLOW COMMAND</p>
      <h1>流影安全态势感知平台</h1>
      <p class="lead">统一接入资产、流量、运行时防护与攻击链事件，面向值守人员的实时安全控制台。</p>
      <div class="signal-strip"><span>ASSET</span><span>TRAFFIC</span><span>XDR</span><span>RASP</span></div>
    </section>

    <section class="login-card" aria-label="登录表单">
      <div class="card-topline" />
      <div class="card-header">
        <div>
          <p>SECURE ACCESS</p>
          <h2>管理员登录</h2>
        </div>
      </div>

      <form class="login-form" @submit.prevent="handleLogin">
        <label>
          <span>账号</span>
          <input
            v-model.trim="form.username"
            type="text"
            placeholder="请输入管理员账号"
            autocomplete="username"
            spellcheck="false"
          >
        </label>

        <label>
          <span>密码</span>
          <input
            v-model="form.password"
            type="password"
            placeholder="请输入密码"
            autocomplete="current-password"
          >
        </label>

        <div v-if="error" class="notice error">{{ error }}</div>

        <button type="submit" :disabled="loading">
          <span v-if="!loading">进入控制台</span>
          <span v-else class="spinner" />
        </button>
      </form>

    </section>
    <div class="device-label">安全运营控制台</div>
  </main>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
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
    await authStore.login({
      username: form.value.username,
      password: form.value.password,
    })
    router.push(authStore.needsPasswordChange ? '/change-password' : '/dashboard')
  } catch (e) {
    error.value = e?.message || '登录失败，请检查凭证'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.auth-page{min-height:100vh;display:grid;grid-template-columns:minmax(0,1fr) 430px;gap:56px;align-items:center;padding:64px clamp(32px,7vw,110px);color:#e5edf8;background:radial-gradient(circle at 18% 16%,rgba(56,189,248,.16),transparent 30%),radial-gradient(circle at 82% 8%,rgba(52,211,153,.12),transparent 28%),linear-gradient(135deg,#07111f,#0f172a 52%,#020617);overflow:hidden;position:relative}
.auth-page::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(56,189,248,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.07) 1px,transparent 1px);background-size:46px 46px;mask-image:linear-gradient(90deg,#000,transparent 76%)}
.brand-panel,.login-card{position:relative;z-index:1}.brand-panel{transform:translateY(-32px)}
.eyebrow{margin:0;color:#38bdf8;font-size:12px;font-weight:900;letter-spacing:.22em}
h1{margin:18px 0;max-width:760px;font-size:clamp(44px,6vw,76px);line-height:.98;letter-spacing:-.06em;color:#f8fafc}
.lead{max-width:720px;color:#94a3b8;font-size:18px;line-height:1.8}
.signal-strip{display:flex;gap:10px;flex-wrap:wrap;margin-top:28px}.signal-strip span{padding:8px 12px;border:1px solid rgba(56,189,248,.26);border-radius:999px;color:#bae6fd;background:rgba(15,23,42,.82);font-size:12px;font-weight:900;letter-spacing:.14em}
.device-label{position:absolute;z-index:2;left:50%;bottom:26px;transform:translateX(-50%);color:#38bdf8;letter-spacing:.22em;font-size:12px;font-weight:850;white-space:nowrap}
.login-card{padding:34px;border-radius:24px;background:#0f172a;border:1px solid rgba(148,163,184,.22);box-shadow:0 30px 100px rgba(0,0,0,.34);overflow:hidden}
.card-topline{position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,#38bdf8,#34d399)}
.card-header{display:flex;align-items:center;gap:16px;margin-bottom:34px}.card-header p{margin:0 0 8px;color:#38bdf8;font-size:11px;font-weight:900;letter-spacing:.18em}.card-header h2{margin:0;font-size:30px;color:#f8fafc}
.login-form{display:grid;gap:18px}label{display:grid;gap:8px;color:#cbd5e1;font-size:13px;font-weight:800}
input{height:46px;border-radius:13px;border:1px solid rgba(148,163,184,.28);background:#111c2f;color:#f8fafc;padding:0 14px;outline:none}input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.14)}
button{height:48px;border:0;border-radius:14px;background:linear-gradient(135deg,#38bdf8,#34d399);color:#04111f;font-weight:950;cursor:pointer}button:disabled{opacity:.68;cursor:not-allowed}
.notice{padding:10px 12px;border-radius:12px;font-size:13px}.notice.error{color:#fecaca;background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.24)}
.spinner{display:inline-block;width:18px;height:18px;border:2px solid rgba(4,17,31,.3);border-top-color:#04111f;border-radius:999px;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:920px){.auth-page{grid-template-columns:1fr;padding:36px 20px}.brand-panel{transform:none}.login-card{max-width:480px;width:100%}}
</style>
