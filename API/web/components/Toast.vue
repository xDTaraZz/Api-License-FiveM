<script setup>
defineProps({
  message: { type: String, default: '' },
  kind: { type: String, default: '' },
  show: { type: Boolean, default: false },
});
</script>

<template>
  <transition name="toast-fade">
    <div v-if="show" class="toast" :class="kind">{{ message }}</div>
  </transition>
</template>

<style scoped>
.toast {
  position: fixed;
  bottom: 22px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--panel2);
  border: 1px solid var(--line);
  color: var(--text);
  padding: 12px 18px;
  border-radius: 12px;
  font-size: 14px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
  z-index: 100;
}
.toast.ok { border-color: var(--green); }
.toast.err { border-color: var(--red); }

.toast-fade-enter-active,
.toast-fade-leave-active { transition: opacity 0.2s, transform 0.2s; }
.toast-fade-enter-from,
.toast-fade-leave-to { opacity: 0; transform: translateX(-50%) translateY(8px); }
</style>
