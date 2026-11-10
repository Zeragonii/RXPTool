'use strict';

// All destinations are private publisher settings, not exposed by the
// standalone public downloader. No navigation link grants authentication.
(() => {
  const form = document.getElementById('navigation-form');
  const editor = document.getElementById('editor-url');
  const publicUrl = document.getElementById('public-url');
  const status = document.getElementById('navigation-status');
  const save = document.getElementById('navigation-save');
  const navDecrypt = document.getElementById('nav-decrypt');
  const navEncrypt = document.getElementById('nav-encrypt');
  const navPublic = document.getElementById('nav-public');

  function showStatus(message, error = false) {
    status.textContent = message;
    status.classList.toggle('error', error);
  }

  function configureLink(link, address) {
    link.hidden = !address;
    if (address) {
      link.href = address;
    } else {
      link.removeAttribute('href');
    }
  }

  function apply(settings) {
    editor.value = settings.editor_url || '';
    publicUrl.value = settings.public_url || '';
    const base = settings.editor_url || '';
    configureLink(navDecrypt, base ? base + '/' : '');
    configureLink(navEncrypt, base ? base + '/encrypt' : '');
    configureLink(navPublic, settings.public_url || '');
  }

  async function init() {
    const response = await fetch('/api/state', {
      credentials: 'same-origin', cache: 'no-store'
    });
    if (response.status === 401) {
      window.location.assign('/login');
      return;
    }
    if (!response.ok) throw Error('Could not load navigation settings');
    const data = await response.json();
    apply(data.navigation || {});
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    save.disabled = true;
    showStatus('Saving workspace links…');
    try {
      const response = await fetch('/api/settings/navigation', {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-RXP-Admin': '1'
        },
        body: JSON.stringify({
          editor_url: editor.value,
          public_url: publicUrl.value
        })
      });
      if (response.status === 401) {
        window.location.assign('/login');
        return;
      }
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw Error(data.error || 'Could not save navigation settings');
      apply(data.navigation);
      showStatus('Saved. Your workspace links are ready above.');
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      save.disabled = false;
    }
  });

  init().catch(error => showStatus(error.message, true));
})();
