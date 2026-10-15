(function () {
  const latest = {};

  function key(deviceId, ip) {
    return deviceId + '|' + ip;
  }

  function csrfToken() {
    return document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function badge(b) {
    if (b.status === 'Blocked' && b.unblock_requested) return '<span class="badge badge-unblocking">Unblocking</span>';
    if (b.status === 'Blocked') return '<span class="badge badge-blocked">Blocked</span>';
    if (b.status === 'Pending') return '<span class="badge badge-pending">Block pending</span>';
    if (b.status === 'Failed') return '<span class="badge badge-failed" title="' + escapeHtml(b.message) + '">Block failed</span>';
    if (b.status === 'Expired') return '<span class="badge badge-expired">Block expired</span>';
    return '<span class="badge badge-resolved">Unblocked</span>';
  }

  function readConfig(el) {
    const holder = el.closest('[data-block-url-template]') || el;
    let durations = [];
    try { durations = JSON.parse(holder.dataset.durations || '[]'); } catch (e) { durations = []; }
    return {
      canManage: holder.dataset.canManageAlerts === 'true',
      blockUrl: holder.dataset.blockUrlTemplate || '',
      unblockUrl: holder.dataset.unblockUrlTemplate || '',
      durations: durations,
    };
  }

  function renderCell(cfg, alertId, b) {
    let html = b ? badge(b) : '';
    if (!cfg.canManage) return html;
    const active = b && (b.status === 'Pending' || b.status === 'Blocked') && !b.unblock_requested;
    const unblocking = b && b.status === 'Blocked' && b.unblock_requested;
    if (active) {
      html += '<form method="post" action="' + cfg.unblockUrl.replace('999999', b.id) + '" class="inline-form">' +
        '<input type="hidden" name="csrfmiddlewaretoken" value="' + csrfToken() + '">' +
        '<button type="submit" class="btn btn-danger">Unblock</button></form>';
    } else if (!unblocking) {
      const options = cfg.durations.map(d => '<option value="' + d[0] + '">' + escapeHtml(d[1]) + '</option>').join('');
      html += '<form method="post" action="' + cfg.blockUrl.replace('999999', alertId) + '" class="block-form">' +
        '<input type="hidden" name="csrfmiddlewaretoken" value="' + csrfToken() + '">' +
        '<select name="mode" class="select-filter"><option value="ip">Whole IP</option><option value="port">IP + port</option></select>' +
        '<select name="duration" class="select-filter">' + options + '</select>' +
        '<button type="submit" class="btn btn-accent">Block</button></form>';
    }
    return html;
  }

  function cellFor(cfg, alert) {
    const b = latest[key(alert.device_id, alert.source_ip)];
    return '<td class="block-cell" data-device-id="' + escapeHtml(alert.device_id) + '" data-ip="' + escapeHtml(alert.source_ip) +
      '" data-alert-id="' + alert.id + '">' + renderCell(cfg, alert.id, b) + '</td>';
  }

  document.addEventListener('entronx:block', function (e) {
    const b = e.detail;
    const k = key(b.device_id, b.ip_address);
    if (latest[k] && latest[k].id > b.id) return;
    latest[k] = b;
    document.querySelectorAll('td.block-cell').forEach(function (cell) {
      if (cell.dataset.deviceId === b.device_id && cell.dataset.ip === b.ip_address) {
        cell.innerHTML = renderCell(readConfig(cell), cell.dataset.alertId, b);
      }
    });
  });

  window.IntrusionXBlocks = { latest: latest, key: key, badge: badge, readConfig: readConfig, renderCell: renderCell, cellFor: cellFor, escapeHtml: escapeHtml, csrfToken: csrfToken };
})();