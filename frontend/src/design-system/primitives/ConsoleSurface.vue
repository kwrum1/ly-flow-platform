<template>
  <section class="ly-console-surface">
    <header v-if="$slots.header" class="ly-console-surface__header">
      <slot name="header" />
    </header>
    <div
      class="ly-console-surface__body"
      :class="{ 'ly-console-surface__body--flush': flush }"
    >
      <slot />
    </div>
  </section>
</template>

<script setup>
defineOptions({ name: 'ConsoleSurface' })

defineProps({
  flush: { type: Boolean, default: false },
})
</script>
