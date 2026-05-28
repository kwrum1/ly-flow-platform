<template>
  <section class="commercial-page">
    <header class="page-hero">
      <p>{{ eyebrow }}</p>
      <h2>{{ title }}</h2>
      <span>{{ description }}</span>
    </header>

    <div class="content-grid">
      <article class="surface-card main-card">
        <div class="card-heading">
          <strong>{{ primaryTitle }}</strong>
          <em>{{ primaryHint }}</em>
        </div>
        <ul class="api-list">
          <li v-for="route in routes" :key="`${route.method}-${route.path}`">
            <span>{{ route.feature }}</span>
            <code>{{ route.method }} {{ route.path }}</code>
          </li>
        </ul>
      </article>

      <aside class="surface-card side-card">
        <strong>产品原则</strong>
        <p>该页面仅展示已经纳入后端契约的能力。后续实现必须读取真实接口、真实持久化数据和真实状态。</p>
      </aside>
    </div>
  </section>
</template>

<script setup>
defineProps({
  eyebrow: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  primaryTitle: { type: String, default: '后端能力契约' },
  primaryHint: { type: String, default: '所有展示均由接口驱动' },
  routes: { type: Array, default: () => [] },
})
</script>

<style scoped>
.commercial-page {
  display: grid;
  gap: 22px;
  padding: 28px;
}

.page-hero {
  padding: 28px;
  border: 1px solid var(--border-light);
  border-radius: 24px;
  background: linear-gradient(135deg, rgba(17, 31, 52, 0.92), rgba(8, 18, 32, 0.76));
}

.page-hero p {
  margin: 0 0 8px;
  color: var(--primary-light);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.16em;
}

.page-hero h2 {
  margin: 0;
  font-size: clamp(30px, 4vw, 52px);
  letter-spacing: -0.05em;
}

.page-hero span {
  display: block;
  max-width: 820px;
  margin-top: 12px;
  color: var(--text-secondary);
  font-size: 16px;
  line-height: 1.8;
}

.content-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 22px;
}

.main-card,
.side-card {
  padding: 24px;
}

.card-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.card-heading strong,
.side-card strong {
  font-size: 18px;
}

.card-heading em {
  color: var(--text-muted);
  font-style: normal;
}

.api-list {
  display: grid;
  gap: 10px;
  list-style: none;
}

.api-list li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 13px 14px;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border-light);
}

.api-list span {
  font-weight: 760;
}

.api-list code {
  color: var(--primary-light);
  font-size: 12px;
}

.side-card p {
  margin-top: 12px;
  color: var(--text-secondary);
  line-height: 1.8;
}

@media (max-width: 1040px) {
  .content-grid {
    grid-template-columns: 1fr;
  }
}
</style>
