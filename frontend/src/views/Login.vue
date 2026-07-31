<template>
  <main class="ly-auth-page">
    <section class="ly-auth-brand">
      <div class="ly-auth-brand-copy">
        <XdrLogo class="ly-auth-mark" :size="64" inverse />
        <p>LYFLOW SECURITY</p>
        <h1>流影安全态势感知平台</h1>
        <div class="ly-auth-capabilities" aria-label="平台能力">
          <span>流量检测</span>
          <span>终端防护</span>
          <span>XDR 关联</span>
          <span>ATT&amp;CK</span>
        </div>
      </div>
      <div class="ly-auth-status"><i />安全运营控制台</div>
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
  width: 100%;
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 420px;
  align-items: center;
  gap: clamp(40px, 6vw, 96px);
  padding: 56px clamp(32px, 7vw, 108px);
  overflow-x: hidden;
  background: linear-gradient(90deg, #1769d2 0 68%, #eaf3fb 68%);
  color: #fff;
}

.ly-auth-page * { box-sizing: border-box; }

.ly-auth-brand {
  position: relative;
  min-height: 560px;
  display: flex;
  align-items: center;
  padding: 48px 0;
  overflow: hidden;
  color: #fff;
}

.ly-auth-brand::before {
  content: '';
  position: absolute;
  inset: -60px -30px;
  background-image:
    linear-gradient(rgba(255,255,255,.08) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.08) 1px, transparent 1px);
  background-size: 42px 42px;
}

.ly-auth-brand::after { display: none; }

.ly-auth-brand-copy,
.ly-auth-status { position: relative; z-index: 1; }

.ly-auth-mark {
  margin-bottom: 26px;
}

.ly-auth-brand-copy p {
  margin: 0;
  color: #d8eaff;
  font-size: 12px;
  font-weight: 800;
}

.ly-auth-brand-copy h1 {
  max-width: 560px;
  margin: 14px 0 30px;
  color: #fff;
  font-size: 42px;
  line-height: 1.2;
  font-weight: 800;
  letter-spacing: 0;
}

.ly-auth-capabilities {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.ly-auth-capabilities span {
  padding: 7px 10px;
  border: 1px solid rgba(255,255,255,.32);
  border-radius: 4px;
  background: rgba(7,68,151,.24);
  color: #eef7ff;
  font-size: 12px;
}

.ly-auth-status {
  position: absolute;
  left: 0;
  bottom: 22px;
  display: flex;
  align-items: center;
  gap: 9px;
  color: #dcecff;
  font-size: 12px;
}

.ly-auth-status i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #5ee59d;
  box-shadow: 0 0 0 4px rgba(94,229,157,.18);
}

.ly-auth-form-area {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0;
  background: transparent;
}

.ly-auth-form-box {
  width: 100%;
  padding: 32px;
  border: 1px solid #d7e1eb;
  border-radius: 8px;
  background: #fff;
  box-shadow: 0 18px 48px rgba(15, 60, 105, .18);
}

.ly-auth-header { margin-bottom: 30px; }
.ly-auth-header p {
  margin: 0 0 8px;
  color: #1769d2;
  font-size: 11px;
  font-weight: 900;
}
.ly-auth-header h2 {
  margin: 0 0 8px;
  color: #172033;
  font-size: 28px;
  line-height: 1.25;
}
.ly-auth-header > span { color: #758195; font-size: 13px; }

.ly-auth-form {
  width: 100%;
  display: grid;
  gap: 18px;
}

.ly-auth-form label {
  display: grid;
  gap: 7px;
  color: #354052;
  font-size: 13px;
  font-weight: 700;
}

.ly-auth-form input {
  width: 100%;
  height: 44px;
  padding: 0 13px;
  border: 1px solid #d8e0eb;
  border-radius: 4px;
  background: #fff;
  color: #172033;
  font-size: 14px;
  outline: none;
}

.ly-auth-form input::placeholder { color: #a1abba; }
.ly-auth-form input:focus {
  border-color: #2782e8;
  box-shadow: 0 0 0 3px rgba(39,130,232,.12);
}

.ly-auth-form button {
  width: 100%;
  height: 46px;
  margin-top: 4px;
  border: 0;
  border-radius: 4px;
  background: #1769d2;
  color: #fff;
  font-size: 14px;
  font-weight: 800;
  cursor: pointer;
}

.ly-auth-form button:hover:not(:disabled) { background: #0f5dbc; }
.ly-auth-form button:disabled { opacity: .65; cursor: wait; }

.ly-auth-error {
  padding: 10px 12px;
  border: 1px solid #f2b8b5;
  border-radius: 4px;
  background: #fff3f2;
  color: #b42318;
  font-size: 13px;
}

.ly-auth-spinner {
  display: inline-block;
  width: 18px;
  height: 18px;
  border: 2px solid rgba(255,255,255,.35);
  border-top-color: #fff;
  border-radius: 50%;
  animation: ly-auth-spin .8s linear infinite;
}

@keyframes ly-auth-spin { to { transform: rotate(360deg); } }

@media (max-width: 860px) {
  .ly-auth-page {
    grid-template-columns: 1fr;
    grid-template-rows: 270px auto;
    gap: 0;
    padding: 0 20px 36px;
    background: linear-gradient(180deg, #1769d2 0 310px, #edf4fa 310px);
  }
  .ly-auth-brand {
    min-height: 270px;
    align-items: center;
    padding: 24px 4px;
  }
  .ly-auth-brand::after,
  .ly-auth-status { display: none; }
  .ly-auth-mark {
    margin-bottom: 12px;
  }
  .ly-auth-brand-copy h1 {
    margin: 7px 0 14px;
    font-size: 26px;
  }
  .ly-auth-capabilities span { padding: 5px 8px; }
  .ly-auth-form-area {
    min-height: 0;
    align-items: flex-start;
    padding: 0;
    transform: translateY(-18px);
  }
  .ly-auth-form-box { max-width: 440px; padding: 28px 24px; }
}

@media (max-width: 420px) {
  .ly-auth-brand-copy h1 { font-size: 23px; }
  .ly-auth-capabilities { gap: 6px; }
  .ly-auth-capabilities span { font-size: 11px; }
  .ly-auth-header { margin-bottom: 24px; }
}
</style>
