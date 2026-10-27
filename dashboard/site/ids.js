/* Display sanitized sensor reports. No push permissions or external delivery. */
(function (root) {
  'use strict';
  const number = n => Number.isFinite(n) && n >= 0;
  function validate(r) {
    if (!r || r.schema_version !== 1 || !number(r.generated_at) ||
        typeof r.health !== 'string' || !Array.isArray(r.recent_alerts) ||
        !r.counts_24h || !Object.values(r.counts_24h).every(number) ||
        !r.recent_alerts.every(a => a && number(a.time) && number(a.sid) &&
          [1, 2, 3].includes(a.severity) && typeof a.signature === 'string' &&
          typeof a.src_ip === 'string' && typeof a.dest_ip === 'string' &&
          typeof a.proto === 'string' && typeof a.test === 'boolean')) {
      throw new Error('Invalid IDS report');
    }
    return r;
  }
  function presentation(r, now = Date.now() / 1000, failed = false, reportTime = now) {
    const stale = failed || now - r.generated_at > 120 || r.generated_at > now + 60 || now - reportTime > 120;
    const review = r.counts_24h.review || 0;
    const warnings = Boolean(r.backlog || r.history_limited || (r.errors || []).length);
    const running = r.health === 'Running' && r.stats_fresh && r.stats && now - r.stats.time <= 120;
    return {stale, review, running, warnings,
      state: stale ? 'Report overdue · saved results' : !running ? `Sensor: ${r.health}` :
        warnings ? 'Reporting limited · review status' : review ? `${review} detections · review required` : 'Monitoring · no review alerts in 24h',
      alert: stale || !running || warnings || review > 0 || (r.stats?.capture?.kernel_drops || 0) > 0};
  }
  const api = {validate, presentation};
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (!root.document) return;
  const el = id => root.document.getElementById('ids-' + id);
  const date = n => new Date(n * 1000).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  const count = n => Number(n || 0).toLocaleString();
  let saved = null, reportTime = 0, failed = false, shown = 10;
  function render() {
    if (!saved) return;
    const v = presentation(saved, Date.now() / 1000, failed, reportTime);
    el('state').textContent = v.state;
    root.document.querySelector('.ids-section').dataset.alert = String(v.alert);
    el('health').textContent = v.stale ? 'Report overdue' : v.running ? 'Running' : saved.health;
    el('freshness').textContent = saved.stats ? `Statistics ${date(saved.stats.time)}${v.running ? '' : ' · not confirmed current'}` : 'No current sensor statistics';
    el('count').textContent = count(v.review);
    el('severity').textContent = `High: ${count(saved.counts_24h.severity_1)} · Medium: ${count(saved.counts_24h.severity_2)} · Low: ${count(saved.counts_24h.severity_3)} · Local tests: ${count(saved.counts_24h.tests)}`;
    const c = saved.stats?.capture;
    el('packets').textContent = c ? count(c.kernel_packets) + ' packets' : '—';
    el('drops').textContent = c ? `${count(c.kernel_drops)} dropped · ${count(c.errors)} capture errors${v.running ? '' : ' · saved counters'}` : 'No capture counters';
    const notes = ['Dashboard only: no email or phone messages. Alerts request review; Suricata does not block traffic or change files.'];
    if (v.stale) notes.unshift('Report updates are overdue or unavailable. These results may be out of date.');
    if (saved.backlog) notes.push('The collector is catching up; alert totals may be incomplete.');
    if (saved.history_limited) notes.push('History reached its storage limit; counts may be incomplete.');
    if ((saved.errors || []).length) notes.push('Some log records could not be read; check the collector service.');
    if (saved.counts_24h.decoder_history) notes.push(`${count(saved.counts_24h.decoder_history)} historical unknown-EtherType notices are excluded from review totals; that single decoder rule was disabled during POC tuning.`);
    if (c?.kernel_drops) notes.push('Packet loss means some traffic was not inspected.');
    el('message').textContent = notes.join(' ');
    el('scope').textContent = saved.scope || 'Coverage information unavailable.';
    el('published').textContent = saved.generated_at ? `Sensor report ${date(saved.generated_at)} · up to 7 days / 20,000 retained alerts; showing the latest 50. Rule priority does not confirm a compromise.` : 'Awaiting a readable sensor snapshot.';
    el('alerts-title').textContent = `Recent detections (${saved.recent_alerts.length} shown in report)`;
    const list = el('alert-list'); list.replaceChildren();
    for (const a of saved.recent_alerts.slice(0, shown)) {
      const article = root.document.createElement('article');
      const title = root.document.createElement('strong');
      title.textContent = `${a.test ? 'Local test' : a.suppressed_history ? 'Historical decoder notice' : ['','High','Medium','Low'][a.severity] + ' priority'} · ${a.signature}`;
      const meta = root.document.createElement('p'); meta.className = 'security-note';
      meta.textContent = `${date(a.time)} · SID ${a.sid} · ${a.proto}${a.sid === 2100498 ? ' · also used during setup diagnostics; review context' : ''}`;
      const flow = root.document.createElement('code');
      const endpoint = (ip, port) => port == null ? ip : `${ip.includes(':') ? '[' + ip + ']' : ip}:${port}`;
      flow.textContent = `${endpoint(a.src_ip, a.src_port)} → ${endpoint(a.dest_ip, a.dest_port)}`;
      article.append(title, meta, flow); list.append(article);
    }
    if (!saved.recent_alerts.length) { const p = root.document.createElement('p'); p.textContent = 'No alerts recorded in retained history. This does not establish that traffic is safe.'; list.append(p); }
    el('more').hidden = shown >= saved.recent_alerts.length;
  }
  function receive(report) {
    try { saved = validate(report.ids); reportTime = report.generated_at; failed = false; render(); }
    catch (_) { failed = true; if (saved) render(); else { el('state').textContent = 'Sensor report unavailable'; el('health').textContent = 'Unavailable'; root.document.querySelector('.ids-section').dataset.alert = 'true'; } }
  }
  root.addEventListener('four-security-report', e => receive(e.detail));
  root.addEventListener('four-security-fetch-failed', () => { failed = true; if (saved) render(); else el('state').textContent = 'Report unavailable'; });
  el('more').addEventListener('click', () => { shown += 10; render(); });
  setInterval(render, 10000);
  if (root.fourSecurityReport) receive(root.fourSecurityReport);
})(typeof window === 'object' ? window : globalThis);
