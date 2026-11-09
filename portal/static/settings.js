'use strict';

(() => {
  const form = document.getElementById('public-page-form');
  const headline = document.getElementById('public-headline');
  const message = document.getElementById('public-message');
  const save = document.getElementById('public-page-save');
  const status = document.getElementById('public-page-status');
  const previewHeadline = document.getElementById('public-preview-headline');
  const previewMessage = document.getElementById('public-preview-message');

  function showStatus(text, failed = false) {
    status.textContent = text;
    status.classList.toggle('error', failed);
  }

  function updatePreview() {
    // textContent prevents any administrator-supplied HTML executing.
    previewHeadline.textContent = headline.value;
    previewMessage.textContent = message.value;
  }

  async function loadSettings() {
    const response = await fetch('/api/state', {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    if (response.status === 401) {
      window.location.assign('/login');
      return;
    }
    if (!response.ok) throw new Error('Unable to load public page settings');
    const state = await response.json();
    if (!state.public_page) throw new Error('Public page settings are unavailable');
    headline.value = state.public_page.headline;
    message.value = state.public_page.message;
    updatePreview();
  }

  headline.addEventListener('input', updatePreview);
  message.addEventListener('input', updatePreview);

  form.addEventListener('submit', async event => {
    event.preventDefault();
    save.disabled = true;
    showStatus('Saving public page text…');
    try {
      const response = await fetch('/api/settings/public-page', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'X-RXP-Admin': '1'
        },
        body: JSON.stringify({
          headline: headline.value,
          message: message.value
        })
      });
      if (response.status === 401) {
        window.location.assign('/login');
        return;
      }
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Could not save settings');
      headline.value = result.public_page.headline;
      message.value = result.public_page.message;
      updatePreview();
      showStatus('Saved! The public page will show this text on the next load.');
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      save.disabled = false;
    }
  });

  loadSettings().catch(error => showStatus(error.message, true));
})();
