'use strict';
(() => {
  const byId = (name) => document.getElementById(name);
  const ids = ['encryptForm', 'encryptId', 'rememberEncryptId', 'encryptFile',
    'encryptDrop', 'encryptFileTitle', 'encryptFileDescription', 'clearEncryptFile',
    'encryptError', 'encryptSubmit', 'encryptSubmitLabel', 'encryptEmpty',
    'encryptLoading', 'encryptResult', 'encryptInputSize', 'encryptOutputSize', 'encryptGuideCount',
    'downloadEncrypted', 'recoveryForm', 'recoverFile', 'recoverError',
    'recoverSubmit', 'recoverStatus', 'toggleEncryptId'];
  const missing = ids.filter((name) => !byId(name));
  if (missing.length) {
    const error = document.createElement('p');
    error.className = 'frontend-mismatch'; error.setAttribute('role', 'alert');
    error.textContent = `Outdated RXPTool page or script. Hard refresh (Ctrl+Shift+R). Missing elements: ${missing.join(', ')}`;
    document.body.prepend(error); return;
  }

  const maxFileBytes = 16 * 1024 * 1024;
  const input = byId('encryptId');
  const remember = byId('rememberEncryptId');
  const upload = byId('encryptFile');
  const drop = byId('encryptDrop');
  const error = byId('encryptError');
  const recoverError = byId('recoverError');
  const storageKey = 'rxp-decode-account-id';
  let file = null;
  let download = null;
  let operationId = 0;
  const show = (id, state) => { byId(id).hidden = !state; };
  const sizeLabel = (n) => n >= 1048576 ? `${(n / 1048576).toFixed(2)} MiB` : `${Math.max(1, Math.round(n / 1024))} KiB`;
  const displayError = (node, message) => { node.textContent = message; node.hidden = false; };
  const clearError = (node) => { node.hidden = true; node.textContent = ''; };

  try {
    const saved = localStorage.getItem(storageKey);
    if (saved) { input.value = saved; remember.checked = true; }
  } catch (_) { /* localStorage not available */ }
  const persistId = () => {
    try {
      if (remember.checked) localStorage.setItem(storageKey, input.value.trim());
      else localStorage.removeItem(storageKey);
    } catch (_) { /* localStorage not available */ }
  };
  remember.addEventListener('change', persistId);
  input.addEventListener('input', () => { if (remember.checked) persistId(); reset(); });
  byId('toggleEncryptId').addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    byId('toggleEncryptId').setAttribute('aria-label', isPassword ? 'Hide account ID' : 'Show account ID');
  });

  function reset() {
    operationId++;
    download = null;
    show('encryptEmpty', true);
    show('encryptLoading', false);
    show('encryptResult', false);
  }
  function chooseFile(item) {
    if (!item) return;
    if (item.size > maxFileBytes) {
      displayError(error, 'File is too large. Maximum plaintext file size is 16 MiB.'); return;
    }
    if (item.size < 1) { displayError(error, 'Choose a nonempty file.'); return; }
    file = item; reset(); clearError(error);
    byId('encryptFileTitle').textContent = item.name;
    byId('encryptFileDescription').textContent = `${sizeLabel(item.size)} · Ready for encryption`;
    show('clearEncryptFile', true);
  }
  drop.addEventListener('click', () => upload.click());
  drop.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); upload.click(); }
  });
  upload.addEventListener('change', () => chooseFile(upload.files?.[0]));
  for (const name of ['dragenter', 'dragover']) drop.addEventListener(name, (event) => {
    event.preventDefault(); drop.classList.add('dragging');
  });
  for (const name of ['dragleave', 'drop']) drop.addEventListener(name, (event) => {
    event.preventDefault(); drop.classList.remove('dragging');
  });
  drop.addEventListener('drop', (event) => chooseFile(event.dataTransfer?.files?.[0]));
  byId('clearEncryptFile').addEventListener('click', () => {
    file = null; upload.value = ''; reset();
    byId('encryptFileTitle').textContent = 'Drop your plaintext guide file here';
    byId('encryptFileDescription').textContent = 'or browse your files to upload a combined TXT or split ZIP';
    show('clearEncryptFile', false); clearError(error);
  });

  function bytesToBase64(bytes) {
    // Avoid a single enormous argument spread on larger files.
    const pieces = [];
    for (let i = 0; i < bytes.length; i += 16384) {
      const part = bytes.subarray(i, i + 16384);
      pieces.push(String.fromCharCode(...part));
    }
    return btoa(pieces.join(''));
  }
  const safeFile = (name) => name.replace(/[\\/]/g, '_').replace(/[\x00-\x1f\x7f]/g, '_').slice(0, 180) || 'package.bin';

  async function requestPackage(endpoint, id, source) {
    const encoded = bytesToBase64(new Uint8Array(await source.arrayBuffer()));
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ battle_id: id, filename: source.name, content_base64: encoded }),
      cache: 'no-store',
    });
    if (!response.ok) {
      let message = `Request failed (HTTP ${response.status})`;
      try { message = (await response.json()).error || message; } catch (_) {}
      throw new Error(message);
    }
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    return { blob: await response.blob(), filename: safeFile(match?.[1] || 'encrypted_guides.txt'), guideCount: response.headers.get('X-Guide-Count') };
  }

  function downloadFile(result) {
    const url = URL.createObjectURL(result.blob);
    const a = document.createElement('a');
    a.href = url; a.download = result.filename; a.hidden = true;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }

  byId('encryptForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (byId('encryptSubmit').disabled) return;
    const id = input.value.trim();
    if (!id) { displayError(error, 'Enter the ID to encrypt the guides with.'); input.focus(); return; }
    if (!file) { displayError(error, 'Choose a plaintext guide file first.'); return; }
    persistId(); clearError(error); reset();
    show('encryptEmpty', false); show('encryptLoading', true);
    byId('encryptSubmit').disabled = true;
    byId('encryptSubmitLabel').textContent = 'Encrypting…';
    const epoch = operationId;
    try {
      const result = await requestPackage('/api/encrypt', id, file);
      if (epoch !== operationId) return;
      download = result;
      byId('encryptInputSize').textContent = sizeLabel(file.size);
      byId('encryptOutputSize').textContent = sizeLabel(result.blob.size);
      byId('encryptGuideCount').textContent = result.guideCount || '—';
      show('encryptLoading', false); show('encryptResult', true);
    } catch (exc) {
      if (epoch === operationId) { reset(); displayError(error, exc?.message || 'Could not encrypt this file.'); }
    } finally {
      byId('encryptSubmit').disabled = false;
      byId('encryptSubmitLabel').textContent = 'Encrypt guides';
    }
  });
  byId('downloadEncrypted').addEventListener('click', () => { if (download) downloadFile(download); });

  byId('recoveryForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (byId('recoverSubmit').disabled) return;
    clearError(recoverError);
    byId('recoverStatus').textContent = '';
    const id = input.value.trim();
    const source = byId('recoverFile').files?.[0];
    if (!id) { displayError(recoverError, 'Enter the original package ID above.'); return; }
    if (!source) { displayError(recoverError, 'Select an .rxptool package.'); return; }
    if (!source.name.toLowerCase().endsWith('.rxptool')) {
      displayError(recoverError, 'Only RXPTool .rxptool packages can be opened here.'); return;
    }
    if (source.size > maxFileBytes + 128 * 1024) {
      displayError(recoverError, 'Encrypted package is too large.'); return;
    }
    persistId();
    byId('recoverSubmit').disabled = true;
    byId('recoverSubmit').textContent = 'Opening package…';
    try {
      const result = await requestPackage('/api/open-package', id, source);
      downloadFile(result);
      byId('recoverStatus').textContent = `Verified and downloaded ${result.filename} (${sizeLabel(result.blob.size)}).`;
    } catch (exc) {
      displayError(recoverError, exc?.message || 'Could not open this package.');
    } finally {
      byId('recoverSubmit').disabled = false;
      byId('recoverSubmit').textContent = 'Open & download original';
    }
  });
})();
