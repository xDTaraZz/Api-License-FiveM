<script setup>
import { ref } from 'vue';

defineProps({
  result: { type: Object, default: null },
});

const emit = defineEmits(['generate', 'copy']);

const ip = ref('');
const days = ref('');
const note = ref('');

function generate() {
  emit('generate', { ip: ip.value.trim(), days: days.value, note: note.value.trim() });
}

function reset() {
  ip.value = '';
  days.value = '';
  note.value = '';
}

defineExpose({ reset });
</script>

<template>
  <section class="card">
    <h2>ออก License (ใส่ IP แล้วได้ Token)</h2>
    <div class="row">
      <input v-model="ip" placeholder="IP เซิร์ฟเวอร์ลูกค้า (เช่น 154.x.x.x)" @keydown.enter="generate" />
      <input v-model="days" type="number" min="0" placeholder="วันหมดอายุ (เว้นว่าง = ตลอดชีพ)" />
      <input v-model="note" placeholder="โน้ต / ชื่อลูกค้า" />
      <button class="btn" @click="generate">Generate Token</button>
    </div>

    <div v-if="result" class="result">
      <h3>พร้อมใช้งาน</h3>
      <div class="kv">
        <b>TOKEN</b><code>{{ result.token }}</code>
        <span class="copy" @click="emit('copy', result.token)">copy</span>
      </div>
      <div class="kv"><b>IP locked</b><code>{{ result.ip_locked || '(bind on first)' }}</code></div>

      <div class="hint">ส่งให้ลูกค้า — วางใน <b>config.lua</b>:</div>
      <pre>{{ result.configSnippet }}</pre>
      <span class="copy" @click="emit('copy', result.configSnippet)">copy config.lua</span>
    </div>
  </section>
</template>

<style scoped>
.hint { margin-top: 10px; color: var(--muted); }
</style>
