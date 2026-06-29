<script setup>
defineProps({
  license: { type: Object, default: null },
  logs: { type: Array, default: () => [] },
});

const emit = defineEmits(['close', 'reset', 'delete', 'copy']);

function fmt(v) {
  return v ? new Date(v).toLocaleString() : '-';
}
function expiry(v) {
  return v ? new Date(v).toLocaleString() : 'lifetime';
}
</script>

<template>
  <div v-if="license" class="overlay" @click.self="emit('close')">
    <div class="modal">
      <div class="modal-head">
        <h2>License Info</h2>
        <button class="x" @click="emit('close')">✕</button>
      </div>

      <div class="info-grid">
        <div class="kv"><b>Token</b><code>{{ license.token }}</code><span class="copy" @click="emit('copy', license.token)">copy</span></div>
        <div class="kv"><b>Product</b><span>{{ license.product_id }}</span></div>
        <div class="kv"><b>Status</b><span class="status" :class="license.status">{{ license.status }}</span></div>
        <div class="kv"><b>IP locked</b><span>{{ license.ip_locked || '(not bound)' }}</span></div>
        <div class="kv"><b>Last IP</b><span>{{ license.last_ip || '-' }}</span></div>
        <div class="kv"><b>Last seen</b><span>{{ fmt(license.last_seen_at) }}</span></div>
        <div class="kv"><b>Owner</b><span>{{ license.owner_name || '-' }}</span></div>
        <div class="kv"><b>Contact</b><span>{{ license.owner_contact || '-' }}</span></div>
        <div class="kv"><b>Note</b><span>{{ license.note || '-' }}</span></div>
        <div class="kv"><b>Created</b><span>{{ fmt(license.created_at) }}</span></div>
        <div class="kv"><b>Expires</b><span>{{ expiry(license.expires_at) }}</span></div>
      </div>

      <h3>Recent verify logs</h3>
      <div class="logs">
        <table class="grid">
          <thead><tr><th>Time</th><th>IP</th><th>Action</th><th>Result</th><th>Message</th></tr></thead>
          <tbody>
            <tr v-if="!logs.length"><td colspan="5" class="empty">— ไม่มี log —</td></tr>
            <tr v-for="g in logs" :key="g.id">
              <td>{{ fmt(g.created_at) }}</td>
              <td>{{ g.ip || '-' }}</td>
              <td>{{ g.action || '-' }}</td>
              <td><span class="result-tag" :class="g.result === 'ok' ? 'ok' : 'bad'">{{ g.result }}</span></td>
              <td>{{ g.message || '' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="modal-foot">
        <button class="btn warn" @click="emit('reset', license.token)">Reset IP</button>
        <button class="btn danger" @click="emit('delete', license.token)">Delete</button>
        <button class="btn ghost" @click="emit('close')">ปิด</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.overlay {
  position: fixed; inset: 0; background: rgba(4, 6, 12, 0.66);
  display: flex; align-items: center; justify-content: center; z-index: 50; padding: 18px;
}
.modal {
  background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
  width: 100%; max-width: 760px; max-height: 88vh; overflow-y: auto; padding: 20px;
}
.modal-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.modal-head h2 { margin: 0; font-size: 18px; }
.x { background: none; border: none; color: var(--muted); font-size: 18px; cursor: pointer; }
.x:hover { color: var(--text); }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 22px; margin-bottom: 18px; }
h3 { font-size: 14px; color: var(--muted); margin: 6px 0 8px; }
.logs { max-height: 240px; overflow-y: auto; }
.empty { text-align: center; color: var(--muted); padding: 14px; }
.result-tag { padding: 2px 9px; border-radius: 999px; font-size: 12px; border: 1px solid var(--line); }
.result-tag.ok { color: var(--green); border-color: var(--green); }
.result-tag.bad { color: var(--red); border-color: var(--red); }
.modal-foot { display: flex; gap: 8px; justify-content: flex-end; margin-top: 18px; }
@media (max-width: 560px) { .info-grid { grid-template-columns: 1fr; } }
</style>
