const STORAGE_KEY = 'nx_admin_key';

let adminKey = localStorage.getItem(STORAGE_KEY) || '';

export function getKey() {
  return adminKey;
}

export function setKey(key) {
  adminKey = key;
  localStorage.setItem(STORAGE_KEY, key);
}

export function clearKey() {
  adminKey = '';
  localStorage.removeItem(STORAGE_KEY);
}

export async function api(path, method = 'GET', body) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Admin-Key': adminKey },
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok || !data || data.ok === false) {
    const message = (data && (data.message || data.code)) || `HTTP ${res.status}`;
    throw new Error(message);
  }
  return data;
}
