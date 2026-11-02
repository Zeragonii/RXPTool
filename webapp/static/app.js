"use strict";
(() => {
  const get = (id) => document.getElementById(id);
  const ids = ['decryptForm','battleId','rememberId','payloadFile','payloadText','error',
    'submitBtn','submitLabel','dropZone','showId','tabUpload','tabPaste','uploadPanel',
    'pastePanel','clearFile','fileTitle','fileDescription','downloadEditable',
    'downloadStatus','emptyState','resultState','loadingState','guideCount',
    'chunkCount','outputSize','previewSuffix','filePreview'];
  const missing = ids.filter(id => !get(id));
  if (missing.length) {
    const error = document.createElement('p'); error.className = 'frontend-mismatch';
    error.textContent = 'RXPTool assets are out of sync. Hard-refresh (Ctrl+Shift+R). Missing: ' + missing.join(', ');
    document.body.prepend(error); return;
  }
  const id = get('battleId'), fileInput = get('payloadFile'), paste = get('payloadText');
  const submit = get('submitBtn'), error = get('error'), drop = get('dropZone');
  const remember = get('rememberId'), key = 'rxp-decode-account-id';
  let mode = 'upload', selected = null, result = null, epoch = 0;
  const visible = (target, state) => { get(target).hidden = !state; };
  const fail = (message) => { error.textContent = message; error.hidden = false; };
  const clearError = () => { error.textContent = ''; error.hidden = true; };
  const size = n => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MiB' : Math.max(1, Math.round(n / 1024)) + ' KiB';
  const saveId = () => { try {
    if (remember.checked) localStorage.setItem(key, id.value.trim());
    else localStorage.removeItem(key);
  } catch (_) {} };
  try { const old = localStorage.getItem(key); if (old) { id.value = old; remember.checked = true; } } catch (_) {}
  remember.addEventListener('change', saveId);
  id.addEventListener('input', () => { if (remember.checked) saveId(); reset(); });
  get('showId').addEventListener('click', () => {
    id.type = id.type === 'password' ? 'text' : 'password';
    get('showId').setAttribute('aria-label', id.type === 'text' ? 'Hide account ID' : 'Show account ID');
  });
  function reset() {
    epoch++; result = null;
    visible('emptyState', true); visible('loadingState', false); visible('resultState', false);
    get('downloadStatus').textContent = '';
  }
  function selectMode(next) {
    mode = next; reset(); clearError();
    visible('uploadPanel', mode === 'upload'); visible('pastePanel', mode === 'paste');
    for (const [button, current] of [['tabUpload', 'upload'],['tabPaste', 'paste']]) {
      get(button).classList.toggle('active', current === mode);
      get(button).setAttribute('aria-selected', String(current === mode));
    }
  }
  get('tabUpload').addEventListener('click', () => selectMode('upload'));
  get('tabPaste').addEventListener('click', () => selectMode('paste'));
  function chooseFile(file) {
    if (!file) return;
    if (file.size > 16 * 1024 * 1024) { fail('Maximum upload size is 16 MiB.'); return; }
    selected = file; reset(); clearError();
    get('fileTitle').textContent = file.name;
    get('fileDescription').textContent = size(file.size) + ' · Ready to decrypt';
    visible('clearFile', true);
  }
  drop.addEventListener('click', () => fileInput.click());
  drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener('change', () => chooseFile(fileInput.files?.[0]));
  ['dragenter','dragover'].forEach(name => drop.addEventListener(name, e => { e.preventDefault(); drop.classList.add('dragging'); }));
  ['dragleave','drop'].forEach(name => drop.addEventListener(name, e => { e.preventDefault(); drop.classList.remove('dragging'); }));
  drop.addEventListener('drop', e => chooseFile(e.dataTransfer?.files?.[0]));
  get('clearFile').addEventListener('click', () => {
    selected = null; fileInput.value = ''; reset();
    get('fileTitle').textContent = 'Drop an encrypted payload here';
    get('fileDescription').textContent = 'or browse your files to select a text export';
    visible('clearFile', false);
  });
  paste.addEventListener('input', reset);
  const downloadBlob = (blob, filename) => {
    const url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = filename; a.hidden = true;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  };
  get('downloadEditable').addEventListener('click', () => {
    if (result) downloadBlob(result, 'editable_guides.txt');
    get('downloadStatus').textContent = 'Downloaded editable_guides.txt · Open Encrypt when your edits are ready.';
  });
  get('decryptForm').addEventListener('submit', async (event) => {
    event.preventDefault(); if (submit.disabled) return;
    const account = id.value.trim();
    if (!account) { fail('Enter the original Battle.net ID.'); id.focus(); return; }
    let payload;
    if (mode === 'upload') {
      if (!selected) { fail('Select an encrypted import first.'); return; }
      try { payload = await selected.text(); } catch (_) { fail('Unable to read the selected file.'); return; }
    } else payload = paste.value;
    if (!payload.trim()) { fail('The encrypted import is empty.'); return; }
    const body = JSON.stringify({battle_id: account, payload, format: 'editable'});
    if (new TextEncoder().encode(body).length > 32 * 1024 * 1024) { fail('Payload exceeds 32 MiB request limit.'); return; }
    saveId(); reset(); clearError();
    const request = epoch; submit.disabled = true;
    get('submitLabel').textContent = 'Decrypting…';
    visible('emptyState', false); visible('loadingState', true);
    try {
      const response = await fetch('/api/decrypt', {method:'POST',
        headers:{'Content-Type':'application/json'}, body, cache:'no-store'});
      if (!response.ok) {
        let message = `Decryption failed (HTTP ${response.status})`;
        try { message = (await response.json()).error || message; } catch (_) {}
        throw new Error(message);
      }
      const blob = await response.blob(); if (request !== epoch) return;
      result = blob;
      const count = Number(response.headers.get('X-Guide-Count') || 0);
      const chunks = Number(response.headers.get('X-Chunk-Count') || 0);
      get('guideCount').textContent = count.toLocaleString();
      get('chunkCount').textContent = chunks.toLocaleString();
      get('outputSize').textContent = size(blob.size);
      let names = [];
      try { const str = response.headers.get('X-Guide-Preview') || '';
        names = JSON.parse(atob(str.replace(/-/g, '+').replace(/_/g, '/')));
      } catch (_) {}
      const ul = get('filePreview'); ul.replaceChildren();
      for (const name of names) {
        const li = document.createElement('li'); li.textContent = name; ul.append(li);
      }
      get('previewSuffix').textContent = `${names.length} of ${count}`;
      visible('loadingState', false); visible('resultState', true);
      get('downloadStatus').textContent = 'Your self-contained editable TXT is ready.';
    } catch (exc) {
      if (request === epoch) { reset(); fail(exc?.message || 'Unable to decrypt the import.'); }
    } finally { submit.disabled = false; get('submitLabel').textContent = 'Decrypt payload'; }
  });
})();
