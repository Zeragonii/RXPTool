'use strict';
const form = document.getElementById('login-form');
const submit = document.getElementById('submit');
const message = document.getElementById('login-status');
form.addEventListener('submit', async event => {
  event.preventDefault();
  submit.disabled = true;
  message.classList.remove('error');
  message.textContent = 'Signing in…';
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-RXP-Login': '1'},
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.error || 'Could not sign in');
    }
    document.getElementById('password').value = '';
    window.location.replace('/admin/publish');
  } catch (error) {
    message.classList.add('error');
    message.textContent = error.message;
    submit.disabled = false;
  }
});
