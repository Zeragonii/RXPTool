'use strict';

// Prefer RFC 5987 filenames for international BattleTags; use the ordinary
// Content-Disposition filename for ASCII IDs (including the # separator).
function downloadName(disposition) {
  const encoded = disposition.match(/(?:^|;)\s*filename\*\s*=\s*UTF-8''([^;]+)/i);
  if (encoded) {
    try {
      return decodeURIComponent(encoded[1].trim());
    } catch (_) {
      // Fall back to the ASCII filename if the extended value is invalid.
    }
  }
  const plain = disposition.match(/(?:^|;)\s*filename\s*=\s*"([^"]+)"/i);
  return plain ? plain[1] : 'RXPTool.txt';
}

const form = document.getElementById('form');
const status = document.getElementById('status');
const button = document.getElementById('submit');

form.addEventListener('submit', async event => {
  event.preventDefault();
  button.disabled = true;
  status.classList.remove('error');
  status.textContent = 'Generating your download…';
  try {
    const response = await fetch('/api/download', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({battle_id: document.getElementById('id').value.trim()}),
      cache: 'no-store'
    });
    if (!response.ok) {
      const details = await response.json().catch(() => ({}));
      throw Error(details.error || 'Download not available');
    }

    const blob = await response.blob();
    const name = downloadName(response.headers.get('Content-Disposition') || '');
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    status.textContent = 'Your guide has been generated.';
  } catch (error) {
    status.classList.add('error');
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
