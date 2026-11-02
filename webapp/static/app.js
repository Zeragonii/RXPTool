'use strict';
(() => {
  const byId = (id) => document.getElementById(id);
  const form = byId('decryptForm');
  const battleId = byId('battleId');
  const remember = byId('rememberId');
  const fileInput = byId('payloadFile');
  const pastedText = byId('payloadText');
  const errorBox = byId('error');
  const submitBtn = byId('submitBtn');
  const submitLabel = byId('submitLabel');
  const dropZone = byId('dropZone');
  const maxFileSize = 16 * 1024 * 1024;
  const storageKey = 'rxp-decode-account-id';
  let mode = 'upload';
  let selectedFile = null;
  let resultBlob = null;
  let resultFilename = null;

  const setVisibility = (id, visible) => { byId(id).hidden = !visible; };
  const showError = (message) => { errorBox.textContent = message; errorBox.hidden = false; };
  const clearError = () => { errorBox.textContent = ''; errorBox.hidden = true; };
  const formatSize = (n) => n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;
  const docIcon = () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M6 3h8l4 4v14H6V3Zm8 0v5h4M9 12h6M9 16h6');
    path.setAttribute('stroke', 'currentColor'); path.setAttribute('stroke-width', '1.6');
    svg.appendChild(path); return svg;
  };
  try {
    const saved = window.localStorage.getItem(storageKey);
    if (saved) { battleId.value = saved; remember.checked = true; }
  } catch (_) { /* Storage unavailable in private browsing. */ }
  const saveIfRequested = () => {
    try {
      if (remember.checked) window.localStorage.setItem(storageKey, battleId.value.trim());
      else window.localStorage.removeItem(storageKey);
    } catch (_) { /* Storage unavailable. */ }
  };
  remember.addEventListener('change', saveIfRequested);
  battleId.addEventListener('input', () => { if (remember.checked) saveIfRequested(); });
  byId('showId').addEventListener('click', () => {
    const hidden = battleId.type === 'password';
    battleId.type = hidden ? 'text' : 'password';
    byId('showId').setAttribute('aria-label', hidden ? 'Hide account ID' : 'Show account ID');
    byId('showId').title = hidden ? 'Hide account ID' : 'Show account ID';
  });
  // Default to showing the ID so users can verify exactly which string is supplied.
  function selectMode(next) {
    mode = next;
    clearError();
    const upload = mode === 'upload';
    setVisibility('uploadPanel', upload);
    setVisibility('pastePanel', !upload);
    for (const [id, active] of [['tabUpload', upload], ['tabPaste', !upload]]) {
      byId(id).classList.toggle('active', active);
      byId(id).setAttribute('aria-selected', String(active));
    }
  }
  byId('tabUpload').addEventListener('click', () => selectMode('upload'));
  byId('tabPaste').addEventListener('click', () => selectMode('paste'));
  function chooseFile(file) {
    if (!file) return;
    if (file.size > maxFileSize) { showError('This file is too large. Maximum upload size is 16 MiB.'); return; }
    selectedFile = file;
    byId('fileTitle').textContent = file.name;
    byId('fileDescription').textContent = `${formatSize(file.size)} · Ready to decrypt`;
    setVisibility('clearFile', true);
    clearError();
  }
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener('change', () => chooseFile(fileInput.files?.[0]));
  for (const eventName of ['dragenter', 'dragover']) dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.add('dragging'); });
  for (const eventName of ['dragleave', 'drop']) dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.remove('dragging'); });
  dropZone.addEventListener('drop', (event) => chooseFile(event.dataTransfer?.files?.[0]));
  byId('clearFile').addEventListener('click', () => {
    selectedFile = null; fileInput.value = '';
    byId('fileTitle').textContent = 'Drop an encrypted payload here';
    byId('fileDescription').innerHTML = 'or <span class="browse-link">browse your files</span> to select a text export';
    setVisibility('clearFile', false);
  });
  function resetResult() { resultBlob = null; resultFilename = null; setVisibility('emptyState', true); setVisibility('resultState', false); setVisibility('loadingState', false); }
  function begin() { clearError(); resultBlob = null; resultFilename = null; setVisibility('emptyState', false); setVisibility('resultState', false); setVisibility('loadingState', true); submitBtn.disabled = true; submitLabel.textContent = 'Processing…'; }
  function end() { submitBtn.disabled = false; submitLabel.textContent = 'Decrypt payload'; }
  function downloadBlob() {
    if (!resultBlob || !resultFilename) return;
    const url = URL.createObjectURL(resultBlob);
    const link = document.createElement('a');
    link.href = url; link.download = resultFilename; link.style.display = 'none';
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }
  byId('downloadBtn').addEventListener('click', downloadBlob);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submitBtn.disabled) return;
    const id = battleId.value.trim();
    if (!id) { showError('Enter your Battle.net ID.'); battleId.focus(); return; }
    let payload = '';
    if (mode === 'upload') {
      if (!selectedFile) { showError('Choose an encrypted payload file first.'); return; }
      if (selectedFile.size > maxFileSize) { showError('This file is too large.'); return; }
      payload = await selectedFile.text();
    } else payload = pastedText.value;
    if (!payload.trim()) { showError('The encrypted payload is empty.'); return; }
    const req = JSON.stringify({ battle_id: id, payload });
    if (new TextEncoder().encode(req).length > maxFileSize) { showError('The payload is too large for this server (16 MiB request limit).'); return; }
    saveIfRequested();
    begin();
    try {
      const response = await fetch('/api/decrypt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: req, cache: 'no-store' });
      if (!response.ok) {
        let text = `Request failed (HTTP ${response.status})`;
        try { const data = await response.json(); text = data.error || text; } catch (_) {}
        throw new Error(text);
      }
      resultBlob = await response.blob();
      const count = Number(response.headers.get('X-Guide-Count') || 0);
      const chunks = Number(response.headers.get('X-Chunk-Count') || 0);
      const disposition = response.headers.get('Content-Disposition') || '';
      resultFilename = /filename="([^"]+)"/.exec(disposition)?.[1] || (count > 1 ? 'decrypted_guides.zip' : 'guide.txt');
      let names = [];
      try {
        const encoded = response.headers.get('X-Guide-Preview') || '';
        const json = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
        names = JSON.parse(json);
      } catch (_) {}
      byId('guideCount').textContent = count.toLocaleString();
      byId('chunkCount').textContent = chunks.toLocaleString();
      byId('outputSize').textContent = formatSize(resultBlob.size);
      byId('previewSuffix').textContent = count > names.length ? `FIRST ${names.length} OF ${count}` : `${count} TOTAL`;
      const preview = byId('filePreview'); preview.replaceChildren();
      for (const name of names) { const li = document.createElement('li'); li.append(docIcon(), document.createTextNode(name)); preview.append(li); }
      byId('downloadText').textContent = count > 1 ? `Download ${count} guides (.zip)` : 'Download decrypted guide';
      byId('downloadHint').textContent = count > 1 ? 'Each guide is a separate .txt file in the archive.' : 'Plaintext is saved as a .txt file.';
      setVisibility('loadingState', false); setVisibility('resultState', true);
    } catch (err) {
      resetResult();
      showError(err?.message || 'Unable to process the payload.');
    } finally { end(); }
  });
})();
