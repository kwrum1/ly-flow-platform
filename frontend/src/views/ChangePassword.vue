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
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 480px;
  align-items: center;
  gap: 56px;
  padding: 64px clamp(28px, 7vw, 108px);
  color: #edf6ff;
  background:
    radial-gradient(circle at 18% 24%, rgba(255, 211, 80, .20), transparent 30%),
    radial-gradient(circle at 82% 16%, rgba(44, 214, 255, .22), transparent 32%),
    linear-gradient(135deg, #06101d, #081423 54%, #02050a);
  box-sizing: border-box;
}
.copy-panel, .change-card { position: relative; z-index: 1; }
.eyebrow { color: #f7d85c; font-size: 12px; letter-spacing: .22em; font-weight: 900; }
h1 { margin: 14px 0 18px; max-width: 720px; font-size: clamp(42px, 5.5vw, 70px); line-height: 1; letter-spacing: -0.055em; }
.copy-panel p:not(.eyebrow) { max-width: 560px; color: #a9bad0; font-size: 18px; line-height: 1.8; }
.rule-card { margin-top: 34px; display: grid; gap: 12px; max-width: 440px; }
.rule { display: flex; gap: 12px; align-items: center; padding: 14px 16px; border-radius: 16px; color: #a8b8ca; background: rgba(255,255,255,.055); border: 1px solid rgba(255,255,255,.08); }
.rule span { width: 22px; height: 22px; display: grid; place-items: center; border-radius: 50%; background: rgba(255,255,255,.08); color: #d4e5f5; }
.rule.ok { color: #eafff7; border-color: rgba(38,255,198,.28); background: rgba(38,255,198,.10); }
.rule.ok span { background: #24ffc6; color: #03111b; }
.change-card { padding: 34px; border-radius: 28px; background: rgba(8, 18, 32, .86); border: 1px solid rgba(137, 205, 255, .20); box-shadow: 0 30px 90px rgba(0,0,0,.42); backdrop-filter: blur(24px); }
.card-header { margin-bottom: 26px; }
.card-header p { margin: 0 0 7px; color: #65d8ff; font-size: 12px; letter-spacing: .18em; font-weight: 900; }
.card-header h2 { margin: 0; font-size: 30px; }
.form { display: grid; gap: 17px; }
label span { display: block; margin-bottom: 9px; color: #9cafc6; font-size: 13px; }
input { width: 100%; box-sizing: border-box; height: 54px; border: 1px solid rgba(144,202,255,.18); border-radius: 16px; background: rgba(2,9,18,.64); color: #fff; padding: 0 16px; outline: none; font-size: 15px; }
input:focus { border-color: #35d8ff; box-shadow: 0 0 0 4px rgba(53,216,255,.12); }
.strength { display: flex; align-items: center; gap: 12px; }
.strength-track { flex: 1; height: 8px; overflow: hidden; border-radius: 999px; background: rgba(255,255,255,.08); }
.strength-track i { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #ff716b, #f7d85c, #24ffc6); transition: width .2s ease; }
.strength b { color: #f7d85c; }
.notice { border-radius: 14px; padding: 12px 14px; font-size: 14px; }
.error { color: #ffb4b4; background: rgba(255,82,82,.12); border: 1px solid rgba(255,82,82,.25); }
.success { color: #c9ffe9; background: rgba(38,255,198,.12); border: 1px solid rgba(38,255,198,.25); }
button { height: 56px; border: 0; border-radius: 16px; color: #03111b; font-weight: 900; font-size: 16px; background: linear-gradient(135deg, #42ddff, #25ffc6); cursor: pointer; box-shadow: 0 18px 42px rgba(37,255,198,.22); }
button:disabled { opacity: .72; cursor: wait; }
.spinner { display: inline-block; width: 18px; height: 18px; border: 2px solid rgba(3,17,27,.28); border-top-color: #03111b; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 920px) {
  .password-page { grid-template-columns: 1fr; padding: 32px 20px; }
  .copy-panel { display: none; }
  .change-card { max-width: 480px; width: 100%; margin: 0 auto; box-sizing: border-box; }
}
</style>
