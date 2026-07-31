<template>
  <svg
    class="xdr-logo"
    :class="{ 'is-inverse': inverse }"
    :style="{ '--xdr-logo-size': `${size}px` }"
    viewBox="0 0 64 64"
    role="img"
    aria-label="流影 XDR"
  >
    <rect class="xdr-logo__frame" x="2" y="2" width="60" height="60" rx="12" />
    <path class="xdr-logo__link" d="M17 17 47 47M47 17 17 47" />
    <path class="xdr-logo__core" d="m32 22 10 10-10 10-10-10Z" />
    <circle class="xdr-logo__node" cx="17" cy="17" r="4" />
    <circle class="xdr-logo__node" cx="47" cy="17" r="4" />
    <circle class="xdr-logo__node" cx="17" cy="47" r="4" />
    <circle class="xdr-logo__node" cx="47" cy="47" r="4" />
    <circle class="xdr-logo__pulse" cx="32" cy="32" r="3" />
  </svg>
</template>

<script setup>
defineProps({
  size: { type: Number, default: 40 },
  inverse: { type: Boolean, default: false },
})
</script>

<style scoped>
.xdr-logo {
  display: block;
  width: var(--xdr-logo-size);
  height: var(--xdr-logo-size);
  flex: 0 0 var(--xdr-logo-size);
}
.xdr-logo__frame { fill: #1769d2; stroke: #1769d2; stroke-width: 2; }
.xdr-logo__link { fill: none; stroke: #c9efff; stroke-width: 2.5; stroke-linecap: round; }
.xdr-logo__core { fill: #fff; stroke: #fff; stroke-width: 2; }
.xdr-logo__node { fill: #62e7d8; stroke: #fff; stroke-width: 2; }
.xdr-logo__pulse { fill: #1769d2; }
.is-inverse .xdr-logo__frame { fill: rgba(255, 255, 255, .12); stroke: rgba(255, 255, 255, .72); }
.is-inverse .xdr-logo__link { stroke: #d9f5ff; }
.is-inverse .xdr-logo__core { fill: #fff; stroke: #fff; }
.is-inverse .xdr-logo__node { fill: #56e0c1; stroke: #fff; }
.is-inverse .xdr-logo__pulse { fill: #1769d2; }
</style>
