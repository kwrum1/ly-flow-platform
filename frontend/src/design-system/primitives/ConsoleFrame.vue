<template>
  <div class="ly-console ly-console-frame">
    <aside class="ly-console-frame__rail" aria-label="Primary navigation">
      <slot name="rail" />
    </aside>
    <aside class="ly-console-frame__navigation" aria-label="Secondary navigation">
      <slot name="navigation" />
    </aside>
    <main class="ly-console-frame__workspace">
      <slot />
    </main>
  </div>
</template>

<script setup>
defineOptions({ name: 'ConsoleFrame' })
</script>
