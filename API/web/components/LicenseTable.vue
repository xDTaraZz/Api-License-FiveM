<script setup>
defineProps({
  licenses: { type: Array, default: () => [] },
});

const emit = defineEmits(['info', 'reset', 'delete', 'refresh']);

function fmtDate(v) {
  return v ? new Date(v).toLocaleDateString() : 'lifetime';
}
function fmtSeen(v) {
  return v ? new Date(v).toLocaleString() : '-';
}
</script>

<template>
  <section class="card">
    <div class="card-head">
      <h2>Licenses</h2>
      <button class="btn ghost small" @click="emit('refresh')">รีเฟรช</button>
    </div>
    <table class="grid">
      <thead>
        <tr>
          <th>Token</th><th>IP locked</th><th>Status</th><th>Last seen</th><th>Expires</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="!licenses.length">
          <td colspan="6" class="empty">— ยังไม่มี license —</td>
        </tr>
        <tr v-for="l in licenses" :key="l.token">
          <td class="token">{{ l.token }}</td>
          <td>{{ l.ip_locked || '-' }}</td>
          <td><span class="status" :class="l.status">{{ l.status }}</span></td>
          <td>{{ fmtSeen(l.last_seen_at) }}</td>
          <td>{{ fmtDate(l.expires_at) }}</td>
          <td class="actions">
            <button class="btn ghost small" @click="emit('info', l.token)">Info</button>
            <button class="btn warn small" @click="emit('reset', l.token)">Reset IP</button>
            <button class="btn danger small" @click="emit('delete', l.token)">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<style scoped>
.empty { text-align: center; color: var(--muted); padding: 18px; }
</style>
