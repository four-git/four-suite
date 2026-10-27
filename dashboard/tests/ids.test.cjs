const {test} = require('node:test');
const assert = require('node:assert/strict');
const ids = require('../site/ids.js');
const base = () => ({schema_version: 1, generated_at: 1000, health: 'Running', stats_fresh: true,
  counts_24h: {}, recent_alerts: [], stats: {time: 995, capture: {kernel_drops: 0}}});
test('fresh sensor and zero alerts still describe monitoring, not safety', () => {
  assert.equal(ids.presentation(ids.validate(base()), 1010).state, 'Monitoring · no review alerts in 24h');
  assert.equal(ids.presentation(base(), 1010).alert, false);
});
test('review detections, capture loss, and reporting backlog draw attention', () => {
  const r = base(); r.counts_24h.review = 2;
  assert.equal(ids.presentation(r, 1010).review, 2);
  assert.equal(ids.presentation(r, 1010).alert, true);
  r.counts_24h = {}; r.stats.capture.kernel_drops = 1;
  assert.equal(ids.presentation(r, 1010).alert, true);
  r.stats.capture.kernel_drops = 0; r.backlog = true;
  assert.equal(ids.presentation(r, 1010).warnings, true);
});
test('stale snapshot, stopped sensor and failed fetch cannot appear healthy', () => {
  assert.equal(ids.presentation(base(), 1201).stale, true);
  assert.equal(ids.presentation(base(), 1010, true).stale, true);
  assert.equal(ids.presentation(base(), 1010, false, 800).stale, true);
  const r = base(); r.health = 'Stopped';
  assert.equal(ids.presentation(r, 1010).running, false);
  assert.equal(ids.presentation(r, 1010).alert, true);
});
test('invalid severity and malformed report are rejected', () => {
  assert.throws(() => ids.validate({schema_version: 2}));
  const r = base(); r.counts_24h.review = -1;
  assert.throws(() => ids.validate(r));
  r.counts_24h = {}; r.recent_alerts = [{time: 1000, sid: 1, severity: 99}];
  assert.throws(() => ids.validate(r));
});
