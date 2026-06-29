<script setup>
import { ref } from 'vue';

defineProps({
  products: { type: Array, default: () => [] },
  selectedId: { type: String, default: '' },
});

const emit = defineEmits(['select', 'create', 'delete']);

const newName = ref('');

function create() {
  if (!newName.value.trim()) return;
  emit('create', newName.value.trim());
  newName.value = '';
}
</script>

<template>
  <aside class="sidebar">
    <div class="side-head">Resources</div>

    <div class="reslist">
      <div v-if="!products.length" class="empty-side">— ยังไม่มี resource —</div>
      <div
        v-for="p in products"
        :key="p.id"
        class="resitem"
        :class="{ active: p.id === selectedId }"
        @click="emit('select', p.id)"
      >
        <div class="resinfo">
          <div class="resname">{{ p.name }}</div>
          <div class="resmeta">{{ p.licenses }} keys</div>
        </div>
        <button class="resdel" title="ลบ resource" @click.stop="emit('delete', p.id)">✕</button>
      </div>
    </div>

    <div class="side-create">
      <input v-model="newName" placeholder="ชื่อ resource ใหม่" @keydown.enter="create" />
      <button class="btn small" @click="create">+ สร้าง</button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 14px;
  display: flex;
  flex-direction: column;
  height: fit-content;
  position: sticky;
  top: 18px;
}
.side-head {
  font-size: 13px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin: 4px 4px 12px;
}
.reslist { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
.empty-side { color: var(--muted); font-size: 13px; padding: 10px 6px; }
.resitem {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid transparent;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.resitem:hover { background: var(--panel2); }
.resitem.active { background: var(--panel2); border-color: var(--accent); }
.resname { font-weight: 600; font-size: 14px; }
.resmeta { font-size: 12px; color: var(--muted); margin-top: 2px; }
.resdel {
  background: none;
  border: none;
  color: var(--muted);
  cursor: pointer;
  font-size: 13px;
  padding: 4px 6px;
  border-radius: 6px;
}
.resdel:hover { color: var(--red); background: rgba(255, 93, 108, 0.1); }
.side-create { display: flex; gap: 6px; border-top: 1px solid var(--line); padding-top: 12px; }
.side-create input { flex: 1; min-width: 0; }
</style>
