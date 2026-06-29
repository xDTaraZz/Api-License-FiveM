<script setup>
import { ref, reactive, computed, onMounted } from 'vue';
import { api, getKey, setKey, clearKey } from './api.js';
import ResourceSidebar from './components/ResourceSidebar.vue';
import GenerateCard from './components/GenerateCard.vue';
import LicenseTable from './components/LicenseTable.vue';
import InfoModal from './components/InfoModal.vue';
import Toast from './components/Toast.vue';

const keyInput = ref(getKey());
const connected = ref(false);

const products = ref([]);
const productId = ref('');
const licenses = ref([]);
const genResult = ref(null);
const creds = ref(null);
const versionDraft = ref('');

const infoLicense = ref(null);
const infoLogs = ref([]);

const genCard = ref(null);

const toast = reactive({ message: '', kind: '', show: false });
let toastTimer = null;

const selectedName = computed(() => {
  const p = products.value.find((x) => x.id === productId.value);
  return p ? p.name : '';
});

function notify(message, kind = '') {
  toast.message = message;
  toast.kind = kind;
  toast.show = true;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.show = false; }, 2600);
}

async function connect() {
  const k = keyInput.value.trim();
  if (!k) return notify('ใส่ Admin Key ก่อน', 'err');
  setKey(k);
  try {
    await api('/admin/products');
    connected.value = true;
    await loadProducts();
    notify('เชื่อมต่อสำเร็จ', 'ok');
  } catch (e) {
    connected.value = false;
    notify('เชื่อมต่อไม่ได้: ' + e.message, 'err');
  }
}

function disconnect() {
  clearKey();
  connected.value = false;
  keyInput.value = '';
  products.value = [];
  licenses.value = [];
  productId.value = '';
  genResult.value = null;
  creds.value = null;
}

async function loadProducts() {
  const data = await api('/admin/products');
  products.value = data.products;
  const stillExists = products.value.some((p) => p.id === productId.value);
  if (!stillExists) {
    productId.value = '';
    licenses.value = [];
    creds.value = null;
    genResult.value = null;
  }
}

function buildServerSnippet(product) {
  return [
    `    ApiUrl          = '${location.origin}/api/verify',`,
    `    ProductId       = '${product.id}',`,
    `    ProductSecret   = '${product.secret}',`,
    `    EdPublicKey     = '${product.ed_public || ''}',`,
  ].join('\n');
}

function buildConfigSnippet(token) {
  return `Config = {\n    Token = '${token}',\n}`;
}

async function selectResource(id) {
  productId.value = id;
  genResult.value = null;
  creds.value = null;
  await Promise.all([loadCreds(), loadLicenses()]);
}

async function loadCreds() {
  if (!productId.value) { creds.value = null; return; }
  try {
    const data = await api('/admin/products/' + encodeURIComponent(productId.value) + '/secret');
    creds.value = { id: data.product.id, snippet: buildServerSnippet(data.product) };
    versionDraft.value = data.product.version || '';
  } catch {
    creds.value = null;
    versionDraft.value = '';
  }
}

async function saveVersion() {
  if (!productId.value) return;
  try {
    await api('/admin/products/' + encodeURIComponent(productId.value) + '/version', 'PUT', { version: versionDraft.value });
    notify('บันทึก version แล้ว', 'ok');
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function createResource(name) {
  try {
    const data = await api('/admin/products', 'POST', { name });
    notify('สร้าง resource แล้ว', 'ok');
    await loadProducts();
    await selectResource(data.product.id);
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function deleteResource(id) {
  const p = products.value.find((x) => x.id === id);
  if (!confirm(`ลบ resource "${p ? p.name : id}" และคีย์ทั้งหมดในนั้น?`)) return;
  try {
    await api('/admin/products/' + encodeURIComponent(id), 'DELETE');
    notify('ลบ resource แล้ว', 'ok');
    if (productId.value === id) productId.value = '';
    await loadProducts();
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function generate(payload) {
  if (!productId.value) return notify('เลือก resource ก่อน', 'err');
  if (!payload.ip) return notify('ใส่ IP ก่อน', 'err');
  const body = { product_id: productId.value, ip: payload.ip };
  const days = parseInt(payload.days, 10);
  if (Number.isFinite(days) && days > 0) {
    body.expires_at = new Date(Date.now() + days * 86400000).toISOString();
  }
  if (payload.note) body.note = payload.note;

  try {
    const data = await api('/admin/licenses', 'POST', body);
    genResult.value = {
      token: data.license.token,
      ip_locked: data.license.ip_locked,
      configSnippet: buildConfigSnippet(data.license.token),
    };
    genCard.value?.reset();
    await loadLicenses();
    await loadProducts();
    notify('ออก token แล้ว', 'ok');
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function loadLicenses() {
  if (!productId.value) { licenses.value = []; return; }
  const data = await api('/admin/licenses?product_id=' + encodeURIComponent(productId.value));
  licenses.value = data.licenses;
}

async function viewInfo(token) {
  const license = licenses.value.find((l) => l.token === token);
  if (!license) return;
  infoLicense.value = license;
  infoLogs.value = [];
  try {
    const data = await api('/admin/logs?token=' + encodeURIComponent(token) + '&limit=20');
    infoLogs.value = data.logs;
  } catch {
    infoLogs.value = [];
  }
}

async function resetIp(token) {
  try {
    await api('/admin/licenses/' + encodeURIComponent(token) + '/reset-ip', 'POST');
    notify('reset IP แล้ว', 'ok');
    await loadLicenses();
    if (infoLicense.value && infoLicense.value.token === token) {
      infoLicense.value = licenses.value.find((l) => l.token === token) || null;
    }
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function del(token) {
  if (!confirm('ลบ ' + token + ' ?')) return;
  try {
    await api('/admin/licenses/' + encodeURIComponent(token), 'DELETE');
    notify('ลบแล้ว', 'ok');
    if (infoLicense.value && infoLicense.value.token === token) infoLicense.value = null;
    await loadLicenses();
    await loadProducts();
  } catch (e) {
    notify(e.message, 'err');
  }
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notify('คัดลอกแล้ว', 'ok');
  } catch {
    notify('คัดลอกไม่ได้ (ต้องใช้ผ่าน https หรือ localhost)', 'err');
  }
}

onMounted(() => {
  if (getKey()) connect();
});
</script>

<template>
  <div class="app">
    <div v-if="!connected" class="login-screen">
      <div class="login-card">
        <div class="login-logo"><span class="dot"></span> NEXUS</div>
        <div class="login-sub">License Admin Panel</div>
        <input
          v-model="keyInput"
          type="password"
          placeholder="Admin Key"
          class="login-input"
          @keydown.enter="connect"
        />
        <button class="btn login-btn" @click="connect">เข้าสู่ระบบ</button>
        <div class="login-foot">ใส่ Admin Key เพื่อเข้าใช้งานแผงควบคุม</div>
      </div>
    </div>

    <header v-else class="topbar">
      <div class="brand"><span class="dot"></span> NEXUS <small>License Panel</small></div>
      <div class="auth">
        <span class="pill on">online</span>
        <button class="btn ghost small" @click="disconnect">Logout</button>
      </div>
    </header>

    <div v-if="connected" class="layout">
      <ResourceSidebar
        :products="products"
        :selected-id="productId"
        @select="selectResource"
        @create="createResource"
        @delete="deleteResource"
      />

      <main class="content">
        <template v-if="productId">
          <section v-if="creds" class="card">
            <div class="card-head">
              <h2>{{ selectedName }} <small class="muted">— server.lua creds</small></h2>
              <span class="copy" @click="copy(creds.snippet)">copy server.lua</span>
            </div>
            <pre>{{ creds.snippet }}</pre>
            <div class="warn-text">ฝังในตาราง <b>Secure</b> ที่หัว server.lua — เก็บเป็นความลับ ห้ามส่งลูกค้า</div>

            <div class="code-head">
              <h2>Resource Version <small class="muted">— .lua จะเตือนสีเหลืองถ้าเวอร์ชันไม่ตรง</small></h2>
            </div>
            <div class="row">
              <input v-model="versionDraft" placeholder="เช่น 1.0.0" />
              <button class="btn small" @click="saveVersion">บันทึก Version</button>
            </div>
          </section>

          <GenerateCard ref="genCard" :result="genResult" @generate="generate" @copy="copy" />

          <LicenseTable
            :licenses="licenses"
            @info="viewInfo"
            @reset="resetIp"
            @delete="del"
            @refresh="loadLicenses"
          />
        </template>

        <div v-else class="locked">เลือก หรือ สร้าง Resource ทางซ้าย</div>
      </main>
    </div>

    <InfoModal
      :license="infoLicense"
      :logs="infoLogs"
      @close="infoLicense = null"
      @reset="resetIp"
      @delete="del"
      @copy="copy"
    />

    <Toast :message="toast.message" :kind="toast.kind" :show="toast.show" />
  </div>
</template>

<style scoped>
.login-screen {
  min-height: 78vh;
  display: flex;
  align-items: center;
  justify-content: center;
}
.login-card {
  width: 100%;
  max-width: 380px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 34px 28px;
  text-align: center;
  box-shadow: 0 24px 70px rgba(0, 0, 0, 0.45);
}
.login-logo {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: 3px;
  display: inline-flex;
  align-items: center;
  gap: 12px;
}
.login-logo .dot {
  width: 14px; height: 14px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 18px var(--accent);
}
.login-sub { color: var(--muted); font-size: 13px; margin: 6px 0 26px; letter-spacing: 1px; }
.login-input { width: 100%; text-align: center; padding: 13px; font-size: 15px; }
.login-btn { width: 100%; margin-top: 12px; padding: 13px; font-size: 15px; }
.login-foot { color: var(--muted); font-size: 12px; margin-top: 18px; }

.layout {
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 18px;
  align-items: start;
}
.content { min-width: 0; }
.muted { color: var(--muted); font-weight: 500; font-size: 13px; }
.warn-text { margin-top: 10px; color: var(--amber); font-size: 12.5px; }
.code-head { display: flex; align-items: center; justify-content: space-between; margin: 18px 0 8px; }
.code-head h2 { margin: 0; font-size: 15px; }
@media (max-width: 820px) {
  .layout { grid-template-columns: 1fr; }
}
</style>
