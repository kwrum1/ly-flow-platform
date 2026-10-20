<template>
  <section class="sx-page forbidden-page">
    <div class="sx-panel">
      <div class="sx-panel-body">
        <p class="sx-kicker">ACCESS CONTROL</p>
        <h2 class="sx-title">当前账号没有控制台权限</h2>
        <p class="sx-subtitle">当前角色只能访问被授权的业务页面。请联系管理员调整角色，或退出后使用管理员账号登录。</p>
        <div class="sx-head-actions">
          <button class="sx-btn" type="button" @click="$router.back()">返回</button>
          <button class="sx-btn primary" type="button" @click="$router.push('/login')">重新登录</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.forbidden-page { padding-top: 80px; }
.forbidden-page .sx-panel-body { display: grid; gap: 10px; padding: 28px; }
</style>
