<template>
  <main class="password-page">
    <section class="copy-panel">
      <p class="eyebrow">首次登录安全加固</p>
      <h1>首次登录必须修改默认密码</h1>
      <p>为避免默认凭证进入生产环境，请设置符合平台安全基线的新密码。</p>
      <div class="rule-card">
        <div v-for="rule in rules" :key="rule.key" :class="['rule', { ok: rule.ok }]">
          <span>{{ rule.ok ? '✓' : '•' }}</span>
          {{ rule.text }}
        </div>
      </div>
    </section>

    <section class="change-card" aria-label="首次登录密码修改">
      <div class="card-header">
          <p>安全策略</p>
        <h2>设置新密码</h2>
      </div>

      <form class="form" @submit.prevent="handleChangePwd">
        <label>
          <span>当前密码</span>
          <input v-model="form.oldPassword" type="password" placeholder="当前默认密码" autocomplete="current-password">
        </label>

        <label>
          <span>新密码</span>
          <input v-model="form.newPassword" type="password" placeholder="至少 8 位，包含大写字母和特殊字符" autocomplete="new-password">
        </label>

        <div class="strength" aria-label="密码策略完成度">
          <div class="strength-track"><i :style="{ width: strengthWidth }" /></div>
          <b>{{ passedRuleCount }}/3</b>
        </div>

        <label>
          <span>确认新密码</span>
          <input v-model="form.confirmPassword" type="password" placeholder="再次输入新密码" autocomplete="new-password">
        </label>

        <div v-if="error" class="notice error">{{ error }}</div>
        <div v-if="success" class="notice success">{{ success }}</div>

        <button type="submit" :disabled="loading">
          <span v-if="!loading">确认修改并重新登录</span>
          <span v-else class="spinner" />
        </button>
      </form>
    </section>
  </main>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const form = ref({ oldPassword: '', newPassword: '', confirmPassword: '' })
const loading = ref(false)
const error = ref('')
const success = ref('')

const passwordChecks = computed(() => {
  const password = form.value.newPassword
  return {
    length: Array.from(password).length >= 8,
    uppercase: /\p{Lu}/u.test(password),
    special: /[\p{P}\p{S}]/u.test(password),
  }
})

const rules = computed(() => [
  { key: 'length', text: '至少 8 位字符', ok: passwordChecks.value.length },
  { key: 'uppercase', text: '包含至少 1 个大写字母', ok: passwordChecks.value.uppercase },
  { key: 'special', text: '包含特殊字符，例如 ， 。 / ! @ #', ok: passwordChecks.value.special },
])

const passedRuleCount = computed(() => rules.value.filter((rule) => rule.ok).length)
const strengthWidth = computed(() => `${(passedRuleCount.value / rules.value.length) * 100}%`)

watch(form, () => {
  if (error.value) error.value = ''
}, { deep: true })

const validatePassword = () => {
  if (!passwordChecks.value.length) return '新密码至少 8 位'
  if (!passwordChecks.value.uppercase) return '新密码必须包含至少 1 个大写字母'
  if (!passwordChecks.value.special) return '新密码必须包含特殊字符，例如 ， 。 / ! @ #'
  if (form.value.newPassword !== form.value.confirmPassword) return '两次输入的新密码不一致'
  if (form.value.oldPassword === form.value.newPassword) return '新密码不能与当前密码相同'
  return ''
}

const handleChangePwd = async () => {
  error.value = ''
  success.value = ''

  if (!form.value.oldPassword) {
    error.value = '请输入当前密码'
    return
  }

  const validationError = validatePassword()
  if (validationError) {
    error.value = validationError
    return
  }

  loading.value = true
  try {
    await authStore.changePassword({
      oldPassword: form.value.oldPassword,
      newPassword: form.value.newPassword,
    })
    success.value = '密码修改成功，请使用新密码重新登录'
    setTimeout(() => router.push('/login'), 900)
  } catch (e) {
    error.value = e?.message || '修改失败，请检查当前密码'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.password-page {
  display: grid;
  place-items: center;
  min-height: 100vh;
  padding: 24px;
  background: radial-gradient(80% 70% at 10% 6%, var(--v-accent-soft), transparent 60%), var(--v-canvas);
  color: var(--v-ink);
}

.change-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  width: min(880px, 100%);
  border: 1px solid var(--v-line);
  border-radius: var(--v-radius-lg);
  background: var(--v-surface);
  box-shadow: var(--v-shadow-lg);
  overflow: hidden;
}

.copy-panel { padding: 32px 28px; border-right: 1px solid var(--v-line); background: var(--v-accent-soft); }
.eyebrow { margin: 0 0 10px; color: var(--v-accent); font-family: var(--v-mono); font-size: 10px; font-weight: 600; letter-spacing: 0.2em; }
.copy-panel h1, .card-header h2 { margin: 0; color: var(--v-ink); font-size: 21px; font-weight: 650; letter-spacing: -0.02em; }
.copy-panel p { margin: 12px 0 0; color: var(--v-ink-2); font-size: 12.5px; line-height: 1.8; }

.card-header { padding: 24px 26px 0; }
.card-header p { margin: 0 0 4px; color: var(--v-accent); font-family: var(--v-mono); font-size: 10px; letter-spacing: 0.18em; }

.form { display: grid; gap: 12px; padding: 18px 26px 26px; }
.form label { display: grid; gap: 6px; color: var(--v-ink-3); font-size: 11.5px; }
.form input { height: 38px; padding: 0 11px; border: 1px solid var(--v-line-2); border-radius: var(--v-radius-sm); background: var(--v-surface); color: var(--v-ink); font: inherit; font-size: 13px; outline: 0; }
.form input:focus { border-color: var(--v-accent); box-shadow: 0 0 0 3px var(--v-accent-soft); }
.form button { height: 40px; margin-top: 4px; border: 1px solid var(--v-accent); border-radius: var(--v-radius-sm); background: var(--v-accent); color: #fff; font: inherit; font-size: 13px; font-weight: 600; cursor: pointer; }
.form button:hover:not(:disabled) { background: var(--v-accent-2); }
.form button:disabled { opacity: 0.55; cursor: not-allowed; }

.strength { display: grid; gap: 5px; }
.strength-track { height: 4px; overflow: hidden; border-radius: 2px; background: var(--v-surface-3); }
.strength-track i { display: block; height: 100%; background: var(--v-accent); }

.rule-card { padding: 12px 14px; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-2); }
.rule-card b { display: block; margin-bottom: 6px; color: var(--v-ink); font-size: 11.5px; }
.rule { display: flex; align-items: center; gap: 7px; color: var(--v-ink-3); font-size: 11px; line-height: 1.7; }
.rule::before { content: ""; width: 5px; height: 5px; border-radius: 50%; border: 1px solid currentColor; }
.rule.ok { color: var(--v-success); }
.rule.ok::before { background: currentColor; }

.notice, .error { padding: 9px 11px; border: 1px solid var(--v-line); border-left-width: 3px; border-radius: var(--v-radius-sm); background: var(--v-surface-2); color: var(--v-ink-2); font-size: 11.5px; }
.error { border-color: var(--v-critical-line); background: var(--v-critical-soft); color: var(--v-critical); }
.success { border-color: var(--v-success-line); background: var(--v-success-soft); color: var(--v-success); }

.spinner { display: inline-block; width: 13px; height: 13px; border: 2px solid rgb(255 255 255 / 40%); border-top-color: #fff; border-radius: 50%; animation: cp-spin 0.8s linear infinite; }
@keyframes cp-spin { to { transform: rotate(360deg); } }

@media (max-width: 820px) {
  .change-card { grid-template-columns: minmax(0, 1fr); }
  .copy-panel { border-right: 0; border-bottom: 1px solid var(--v-line); }
}
</style>
