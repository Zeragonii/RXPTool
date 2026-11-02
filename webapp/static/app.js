'use strict';
(() => {
  const byId = (id) => document.getElementById(id);
  // Do not crash with an opaque addEventListener error if a caching layer
  // accidentally serves a page and script from different releases.
  const expectedIds = [
    'decryptForm', 'battleId', 'rememberId', 'payloadFile', 'payloadText',
    'error', 'submitBtn', 'submitLabel', 'dropZone', 'showId', 'tabUpload',
    'tabPaste', 'uploadPanel', 'pastePanel', 'clearFile', 'fileTitle',
    'fileDescription', 'downloadCombined', 'downloadSplit', 'downloadStatus',
    'emptyState', 'resultState', 'loadingState', 'guideCount', 'chunkCount',
    'outputSize', 'previewSuffix', 'filePreview'
  ];
  const missingIds = expectedIds.filter((id) => !byId(id));
  if (missingIds.length) {
    const message = 'RXP Decoder assets are out of sync. Refresh the page with Ctrl+Shift+R. ' +
      'Missing UI elements: ' + missingIds.join(', ');
    console.error(message);
    const notice = document.createElement('p');
    notice.className = 'frontend-mismatch';
    notice.setAttribute('role', 'alert');
    notice.textContent = message;
    document.body.prepend(notice);
    return;
  }
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
  // Only the browser holds the submitted payload between export requests.
  // The server is stateless; choosing another format re-decrypts on demand.
  let lastInput = null;
  let exportCache = new Map();
  let exportBusy = false;
  let requestEpoch = 0;

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
    if (mode !== next) resetResult();
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
    resetResult();
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
    resetResult();
    selectedFile = null; fileInput.value = '';
    byId('fileTitle').textContent = 'Drop an encrypted payload here';
    byId('fileDescription').innerHTML = 'or <span class="browse-link">browse your files</span> to select a text export';
    setVisibility('clearFile', false);
  });
  const combinedBtn = byId('downloadCombined');
  const splitBtn = byId('downloadSplit');
  const exportStatus = byId('downloadStatus');

  function resetResult() {
    // If a different ID or payload is entered, discard previous output.
    requestEpoch++;
    lastInput = null;
    exportCache = new Map();
    exportStatus.classList.remove('error');
    setVisibility('emptyState', true);
    setVisibility('resultState', false);
    setVisibility('loadingState', false);
  }
  function begin() {
    clearError();
    resetResult();
    setVisibility('emptyState', false);
    setVisibility('loadingState', true);
    submitBtn.disabled = true;
    submitLabel.textContent = 'Processing…';
  }
  function end() {
    submitBtn.disabled = false;
    submitLabel.textContent = 'Decrypt payload';
  }
  const setExportBusy = (busy) => {
    exportBusy = busy;
    combinedBtn.disabled = busy;
    splitBtn.disabled = busy;
    submitBtn.disabled = busy;
  };
  const setExportStatus = (message, error = false) => {
    exportStatus.textContent = message;
    exportStatus.classList.toggle('error', error);
  };
  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = filename; link.style.display = 'none';
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }
  async function fetchExport(input, outputFormat) {
    const response = await fetch('/api/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...input, format: outputFormat }),
      cache: 'no-store'
    });
    if (!response.ok) {
      let message = `Request failed (HTTP ${response.status})`;
      try { const data = await response.json(); message = data.error || message; } catch (_) {}
      throw new Error(message);
    }
    const blob = await response.blob();
    const count = Number(response.headers.get('X-Guide-Count') || 0);
    const chunks = Number(response.headers.get('X-Chunk-Count') || 0);
    const format = response.headers.get('X-Output-Format') || (count > 1 ? 'split' : 'combined');
    const disposition = response.headers.get('Content-Disposition') || '';
    const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ||
      (format === 'split' ? 'decrypted_guides.zip' : 'decrypted_guides.txt');
    return { response, blob, filename, format, count, chunks };
  }
  async function downloadFormat(format) {
    if (!lastInput || exportBusy || submitBtn.disabled) return;
    let item = exportCache.get(format);
    if (!item) {
      const epoch = requestEpoch;
      setExportBusy(true);
      setExportStatus(format === 'combined' ? 'Preparing combined plaintext…' : 'Preparing split ZIP…');
      try {
        const result = await fetchExport(lastInput, format);
        if (epoch !== requestEpoch) return; // Input changed while processing.
        item = { blob: result.blob, filename: result.filename };
        exportCache.set(format, item);
      } catch (err) {
        setExportStatus(err?.message || 'Unable to prepare the download.', true);
        return;
      } finally {
        setExportBusy(false);
      }
    }
    if (!item) return;
    saveBlob(item.blob, item.filename);
    setExportStatus(format === 'combined'
      ? 'Downloaded one combined plaintext file.'
      : 'Downloaded a ZIP of individual guide files.');
  }
  combinedBtn.addEventListener('click', () => downloadFormat('combined'));
  splitBtn.addEventListener('click', () => downloadFormat('split'));
  battleId.addEventListener('input', resetResult);
  pastedText.addEventListener('input', resetResult);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submitBtn.disabled) return;
    const id = battleId.value.trim();
    if (!id) { showError('Enter your Battle.net ID.'); battleId.focus(); return; }
    let payload = '';
    if (mode === 'upload') {
      if (!selectedFile) { showError('Choose an encrypted payload file first.'); return; }
      if (selectedFile.size > maxFileSize) { showError('This file is too large.'); return; }
      try { payload = await selectedFile.text(); }
      catch (_) { showError('Unable to read the selected file.'); return; }
    } else payload = pastedText.value;
    if (!payload.trim()) { showError('The encrypted payload is empty.'); return; }
    const input = { battle_id: id, payload };
    const req = JSON.stringify({ ...input, format: 'auto' });
    if (new TextEncoder().encode(req).length > maxFileSize) {
      showError('The payload is too large for this server (16 MiB request limit).'); return;
    }
    saveIfRequested();
    begin();
    const epoch = requestEpoch;
    try {
      const result = await fetchExport(input, 'auto');
      if (epoch !== requestEpoch) return;
      lastInput = input;
      exportCache.set(result.format, { blob: result.blob, filename: result.filename });
      let names = [];
      try {
        const encoded = result.response.headers.get('X-Guide-Preview') || '';
        const json = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
        names = JSON.parse(json);
      } catch (_) {}
      byId('guideCount').textContent = result.count.toLocaleString();
      byId('chunkCount').textContent = result.chunks.toLocaleString();
      byId('outputSize').textContent = formatSize(result.blob.size);
      byId('previewSuffix').textContent = result.count > names.length ?
        `FIRST ${names.length} OF ${result.count}` : `${result.count} TOTAL`;
      const preview = byId('filePreview'); preview.replaceChildren();
      for (const name of names) {
        const li = document.createElement('li');
        li.append(docIcon(), document.createTextNode(name)); preview.append(li);
      }
      setExportStatus('Choose either format. You can download both without uploading again.');
      setVisibility('loadingState', false);
      setVisibility('resultState', true);
    } catch (err) {
      if (epoch === requestEpoch) {
        resetResult();
        showError(err?.message || 'Unable to process the payload.');
      }
    } finally { end(); }
  });
})();
