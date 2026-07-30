<template>
  <header class="ly-console-identity">
    <div class="ly-console-identity__copy">
      <h1 class="ly-console-identity__title">{{ title }}</h1>
      <p v-if="context" class="ly-console-identity__context">{{ context }}</p>
    </div>
    <div v-if="$slots.actions" class="ly-console-identity__actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<script setup>
defineOptions({ name: 'ConsoleIdentityRow' })

defineProps({
  title: { type: String, required: true },
  context: { type: String, default: '' },
})
</script>
