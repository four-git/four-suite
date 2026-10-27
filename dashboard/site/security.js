/* Static NAS report reader. No credentials, scanner commands or external dependencies. */
(function (root) {
  'use strict';
  const labels = {POLICY_VIOLATION: 'Executable or script in media · review required', MALWARE_DETECTED: 'Malware detected', YARA_MATCH: 'YARA match · review required', SCAN_ERROR: 'Scan error', FILE_CHANGED: 'File changed · awaiting scan', PARTIALLY_SCANNED: 'Partial engine coverage', SKIPPED_SIZE_LIMIT: 'Skipped · size limit', CLEAN: 'No loaded-engine match', PENDING: 'Pending', SKIPPED_POLICY: 'Policy skip'};
  const number = value => Number.isFinite(value) && value >= 0;
  function validate(report) {
    if (!report || report.schema_version !== 1 || !number(report.generated_at) ||
        !Array.isArray(report.findings) || !Array.isArray(report.recent_runs) ||
        !report.file_counts || typeof report.file_counts !== 'object' || Array.isArray(report.file_counts) ||
        !Object.values(report.file_counts).every(number) || !number(report.retained_scan_count) ||
        !number(report.retention_days) || !number(report.stale_scan_seconds) || typeof report.coverage_note !== 'string') {
      throw new Error('Unsupported or invalid scan report');
    }
    function validRun(run) {
      return run === null || (run && number(run.id) && number(run.started_at) &&
        (run.state === 'running' ? run.ended_at === null : number(run.ended_at)) && number(run.duration_seconds) &&
        ['running', 'completed', 'failed', 'interrupted'].includes(run.state) &&
        ['scan', 'discover'].includes(run.action) && typeof run.dry_run === 'boolean' &&
        run.summary && typeof run.summary === 'object' && number(run.summary.scan_attempts) &&
        number(run.summary.cached) && number(run.summary.visited));
    }
    if (![report.latest_scan, report.latest_completed_scan, report.active_run, ...report.recent_runs].every(validRun) ||
        !report.findings.every(item => item && typeof item.path === 'string' && typeof item.kind === 'string' && number(item.time) &&
          (item.share_path === null || typeof item.share_path === 'string'))) {
      throw new Error('Invalid scan values');
    }
    return report;
  }
  function formatDuration(seconds) {
    if (!number(seconds)) return '—';
    const total = Math.floor(seconds);
    if (total < 60) return `${total}s`;
    if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s`;
    return `${Math.floor(total / 3600)}h ${Math.floor(total % 3600 / 60)}m`;
  }
  function presentation(report, now = Date.now() / 1000, failed = false) {
    const counts = report.file_counts;
    const issues = (counts.MALWARE_DETECTED || 0) + (counts.YARA_MATCH || 0) + (counts.SCAN_ERROR || 0) + (counts.POLICY_VIOLATION || 0);
    const warnings = report.findings.filter(item => !['MALWARE_DETECTED', 'YARA_MATCH', 'SCAN_ERROR', 'POLICY_VIOLATION'].includes(item.kind)).length;
    const outdated = now - report.generated_at > 120 || report.generated_at > now + 60;
    const completed = report.latest_completed_scan;
    const staleScan = !completed || now - completed.ended_at > report.stale_scan_seconds;
    const active = report.active_run;
    let state = !report.latest_scan ? 'No scan recorded' : 'Latest scan recorded';
    if (report.latest_scan && ['failed', 'interrupted'].includes(report.latest_scan.state)) state = `Last scan ${report.latest_scan.state}`;
    if (active) state = active.dry_run ? 'Dry run in progress' : active.action === 'discover' ? 'Discovery in progress' : 'Scan in progress';
    if (issues) state += ' · review required';
    if (failed) state = 'Report unavailable · saved results';
    else if (outdated) state = 'Report outdated · saved results';
    return {issues, warnings, outdated, staleScan, state, alert: failed || outdated || staleScan || issues > 0};
  }
  const api = {validate, formatDuration, presentation};
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (!root.document) return;
  const document = root.document;
  const el = id => document.getElementById(`security-${id}`);
  let saved = null, failed = false, shown = 20;
  const date = stamp => stamp === null || stamp === undefined ? '—' : new Date(stamp * 1000).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  const count = value => (value || 0).toLocaleString();
  function freshness() {
    if (!saved) return;
    const view = presentation(saved, Date.now() / 1000, failed);
    el('state').textContent = view.state;
    document.querySelector('.security-section').dataset.alert = String(Boolean(view.alert));
    const age = Math.max(0, Date.now() / 1000 - saved.generated_at);
    el('published').textContent = `Report published ${date(saved.generated_at)} · ${formatDuration(age)} ago${view.outdated ? ' · publication overdue' : ''}`;
    const notes = [];
    if (failed) notes.push('The latest report could not be read. Showing the last successfully received results.');
    if (view.outdated) notes.push('Report updates have stopped or the publisher clock differs; these results may be out of date.');
    if (view.staleScan) notes.push(saved.latest_completed_scan ? 'The last completed scan is older than the configured freshness threshold.' : 'No completed scan is recorded in retained history.');
    if (saved.latest_scan && saved.latest_scan.failure_reason) notes.push(saved.latest_scan.failure_reason);
    if (!notes.length) notes.push('Latest recorded results. Scan limits and coverage warnings still apply.');
    el('message').textContent = notes.join(' ');
  }
  function findings() {
    const list = el('finding-list');
    list.replaceChildren();
    const fragment = document.createDocumentFragment();
    for (const item of saved.findings.slice(0, shown)) {
      const article = document.createElement('article');
      const title = document.createElement('strong'); title.textContent = labels[item.kind] || item.kind;
      const timestamp = document.createElement('p'); timestamp.className = 'security-note'; timestamp.textContent = `Observed ${date(item.time)}`;
      const path = document.createElement('code'); path.textContent = item.path;
      article.append(title, timestamp, path);
      if (item.share_path) { const share = document.createElement('code'); share.textContent = item.share_path; article.append(share); }
      if (item.evidence) {
        const detail = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Scanner evidence';
        const evidence = document.createElement('pre'); evidence.textContent = typeof item.evidence === 'string' ? item.evidence : JSON.stringify(item.evidence, null, 2);
        detail.append(summary, evidence); article.append(detail);
      }
      fragment.append(article);
    }
    if (!saved.findings.length) { const p = document.createElement('p'); p.textContent = 'No actionable findings in recorded file results. This does not establish full-library coverage.'; fragment.append(p); }
    list.append(fragment);
    el('findings-title').textContent = `Findings and coverage (${count(saved.findings.length)})`;
    el('more').hidden = shown >= saved.findings.length;
    el('more').textContent = `Show more · ${count(Math.max(0, saved.findings.length - shown))} remaining`;
  }
  function render() {
    const completed = saved.latest_completed_scan;
    const view = presentation(saved);
    el('last').textContent = completed ? date(completed.ended_at) : 'No completed scan';
    el('duration').textContent = completed ? `${formatDuration(completed.duration_seconds)} duration · run ${completed.id}` : 'Awaiting a completed real scan';
    el('files').textContent = completed ? count(completed.summary.scan_attempts) : '—';
    el('cached').textContent = completed ? `${count(completed.summary.cached)} cached · ${count(completed.summary.visited)} visited in that run` : 'Actual attempts in the last completed run';
    el('issues').textContent = count(view.issues);
    el('warnings').textContent = `${count(view.warnings)} coverage warnings · ${count(saved.file_counts.PENDING)} pending`;
    const active = saved.active_run;
    el('progress').textContent = active ? `Active ${active.action}${active.dry_run ? ' (dry run)' : ''} · ${formatDuration(active.duration_seconds)} elapsed at publication · ${count(active.summary.scan_attempts)} scanned · ${count(active.summary.cached)} cached · ${count(active.summary.visited)} visited` : '';
    if (completed && completed.summary.discovery_truncated) el('progress').textContent += ' Last completed run reached a discovery or work limit.';
    el('counts').textContent = Object.entries(saved.file_counts).map(([status, total]) => `${labels[status] || status}: ${count(total)}`).join(' · ') || 'No file observations recorded.';
    el('retention').textContent = `${count(saved.retained_scan_count)} real scans in the retained ${saved.retention_days} days · showing the latest ${saved.recent_runs.length}. Counts include repeated attempts, not unique lifetime files.`;
    el('coverage').textContent = saved.coverage_note;
    el('history').replaceChildren();
    for (const run of saved.recent_runs) {
      const tr = document.createElement('tr');
      const counts = run.summary.counts || {};
      const outcome = run.state + (run.summary.discovery_truncated ? ' · limited' : '') + ((counts.MALWARE_DETECTED || counts.YARA_MATCH) ? ' · findings' : '');
      for (const value of [date(run.started_at), outcome, formatDuration(run.duration_seconds), count(run.summary.scan_attempts)]) {
        const td = document.createElement('td'); td.textContent = value; tr.append(td);
      }
      el('history').append(tr);
    }
    findings(); freshness();
  }
  el('more').addEventListener('click', () => { shown += 20; findings(); });
  async function poll() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await root.fetch('data/security/status.json', {cache: 'no-store', credentials: 'omit', signal: controller.signal});
      if (!response.ok) throw new Error('Report unavailable');
      const report = validate(await response.json());
      if (report.generated_at > Date.now() / 1000 + 60) throw new Error('Publisher clock differs');
      saved = report; failed = false; render();
      root.fourSecurityReport = report;
      root.dispatchEvent(new root.CustomEvent('four-security-report', {detail: report}));
    } catch (_) {
      failed = true;
      root.dispatchEvent(new root.CustomEvent('four-security-fetch-failed'));
      if (saved) freshness();
      else {
        el('state').textContent = 'Report unavailable';
        el('message').textContent = root.location.protocol === 'file:' ? 'Open this page through the preview server or Web Station to read scan reports.' : 'No readable scan report is available yet. The page will retry automatically.';
        document.querySelector('.security-section').dataset.alert = 'true';
      }
    } finally { clearTimeout(timeout); setTimeout(poll, 30000); }
  }
  setInterval(freshness, 10000);
  poll();
})(typeof window === 'object' ? window : globalThis);
