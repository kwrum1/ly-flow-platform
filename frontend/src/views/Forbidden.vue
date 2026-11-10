<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">ACCESS CONTROL</p>
        <h1>当前账号没有这个页面的权限</h1>
        <p>
          当前角色（{{ roleLabel }}）只能访问被授权的业务页面。请联系管理员调整角色，
          或返回本角色可访问的首页。
        </p>
      </div>
      <div class="v-head-actions">
        <button class="v-btn" type="button" @click="$router.back()">返回</button>
        <button class="v-btn primary" type="button" @click="$router.push(homePath)">回到态势总览</button>
        <button class="v-btn ghost" type="button" @click="$router.push('/login')">重新登录</button>
      </div>
    </header>

    <article class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">可访问范围</div>
        <span class="v-panel-meta">{{ roleLabel }}</span>
      </div>
      <div class="v-panel-body">
        <p class="hint">
          只读账号可查看态势总览、事件检索与检测面；需要处置、规则或系统配置的页面仅对更高角色开放。
        </p>
        <p class="hint">如果这不符合预期，请让管理员在「系统管理 → 账户」中调整角色后重新登录。</p>
      </div>
    </article>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { useAuthStore } from '../stores/auth'
import { DEFAULT_HOME_PATH } from '../router/roles'

const authStore = useAuthStore()
const homePath = DEFAULT_HOME_PATH
const roleLabel = computed(() => (
  { admin: '管理员', analyst: '分析员', viewer: '只读' }[authStore.user?.role] || '未识别'
))
</script>

<style scoped>
.hint { margin: 0 0 8px; max-width: 820px; color: var(--v-ink-3); font-size: 12.5px; line-height: 1.7; }
.hint:last-child { margin-bottom: 0; }
</style>
