'use strict';

// This script is served by the authenticated publisher only. All values from
// telemetry are rendered with textContent, never inserted as HTML.
(() => {
  const ids = document.getElementById('unapproved-ids');
  const summary = document.getElementById('unapproved-summary');
  const days = document.getElementById('traffic-daily');
  const referrals = document.getElementById('traffic-referrers');
  const status = document.getElementById('traffic-status');
  const refreshButton = document.getElementById('traffic-refresh');
  const number = new Intl.NumberFormat();
  const timestamp = value => {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
  };

  function row(list, label, detail, title = '') {
    const li = document.createElement('li');
    const main = document.createElement('span');
    main.className = 'traffic-row-label';
    main.textContent = label;
    if (title) main.title = title;
    const value = document.createElement('span');
    value.className = 'traffic-row-detail';
    value.textContent = detail;
    li.append(main, value);
    list.append(li);
  }

  function empty(list, message) {
    list.replaceChildren();
    row(list, message, '');
  }

  function setCount(id, value) {
    document.getElementById(id).textContent = number.format(value || 0);
  }

  function show(data) {
    if (!data.available) {
      summary.textContent = 'Tracking unavailable — deploy the updated portal stack with its analytics volume.';
      status.textContent = 'Traffic recording begins only after the new telemetry volume is mounted.';
      return;
    }
    status.textContent = 'Updated ' + timestamp(data.as_of) + '. Data is retained for up to ' +
      data.retention_days + ' days.';
    setCount('traffic-today-views', data.today.views);
    setCount('traffic-week-views', data.week.views);
    setCount('traffic-month-views', data.month.views);
    setCount('traffic-month-successes', data.month.successes);
    setCount('traffic-month-denials', data.month.denials);
    setCount('traffic-month-requests', data.month.requests);

    ids.replaceChildren();
    summary.textContent = number.format(data.unapproved.length) + ' currently unapproved ID(s) seen within the retention period';
    if (!data.unapproved.length) {
      row(ids, 'No unapproved download attempts recorded.', '');
    } else {
      for (const record of data.unapproved) {
        const li = document.createElement('li');
        const info = document.createElement('div');
        info.className = 'traffic-unknown-info';
        const name = document.createElement('strong');
        name.textContent = record.battle_id;
        const detail = document.createElement('small');
        detail.textContent = 'First: ' + timestamp(record.first_seen) +
          ' · Last: ' + timestamp(record.last_seen);
        info.append(name, detail);
        const count = document.createElement('span');
        count.className = 'traffic-attempt-count';
        count.textContent = number.format(record.attempts) +
          (record.attempts === 1 ? ' attempt' : ' attempts');
        li.append(info, count);
        ids.append(li);
      }
    }

    days.replaceChildren();
    if (!data.daily.length) {
      row(days, 'No traffic recorded yet.', '');
    } else {
      for (const day of [...data.daily].reverse()) {
        row(days, day.day, number.format(day.views) + ' · ' +
          number.format(day.successes) + ' · ' + number.format(day.denials));
      }
    }

    referrals.replaceChildren();
    if (!data.referrers.length) {
      row(referrals, 'No external referrers supplied by visitors.', '');
    } else {
      for (const referrer of data.referrers) {
        row(referrals, referrer.hostname, number.format(referrer.views) + ' views');
      }
    }
  }

  async function refresh() {
    refreshButton.disabled = true;
    status.textContent = 'Loading activity…';
    try {
      const response = await fetch('/api/analytics', {
        credentials: 'same-origin', cache: 'no-store'
      });
      if (response.status === 401) {
        window.location.assign('/login');
        return;
      }
      if (!response.ok) throw new Error('Traffic statistics could not be loaded');
      show(await response.json());
    } catch (error) {
      status.textContent = error.message;
      status.classList.add('error');
    } finally {
      refreshButton.disabled = false;
    }
  }
  refreshButton.addEventListener('click', refresh);
  refresh();
})();
