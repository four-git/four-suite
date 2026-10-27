const {test} = require('node:test');
const assert = require('node:assert/strict');
const {validate, presentation, formatDuration} = require('../site/security.js');
const report = () => ({schema_version:1, generated_at:1000, latest_scan:null, latest_completed_scan:null, active_run:null,
  file_counts:{}, findings:[], recent_runs:[], retained_scan_count:0, retention_days:30, stale_scan_seconds:86400, coverage_note:'Bounded scans.'});
const run = () => ({id:1, action:'scan', dry_run:false, state:'completed', started_at:900, ended_at:950,
  duration_seconds:50, summary:{scan_attempts:3, visited:8, cached:5}});

test('active content policy is a review issue rather than a coverage warning', () => {
  const value = report();
  value.file_counts.POLICY_VIOLATION = 1;
  value.findings = [{kind:'POLICY_VIOLATION'}];
  const view = presentation(value, 1000);
  assert.equal(view.issues, 1);
  assert.equal(view.warnings, 0);
  assert.equal(view.alert, true);
});
test('never scanned is distinct from clean', () => {
  const value = validate(report());
  assert.equal(presentation(value,1000).state,'No scan recorded');
  assert.equal(presentation(value,1000).staleScan,true);
});
test('outages and stale publication preserve original timestamp', () => {
  const value=report(); value.latest_scan=value.latest_completed_scan=run();
  assert.equal(presentation(value,1050).outdated,false);
  assert.equal(presentation(value,1121).outdated,true);
  assert.match(presentation(value,1050,true).state,/unavailable/);
  assert.equal(value.generated_at,1000);
});
test('issues, coverage, active runs and failure are distinct', () => {
  const value=report(); value.latest_scan=run(); value.latest_scan.state='failed';
  value.file_counts={MALWARE_DETECTED:2,YARA_MATCH:1,SCAN_ERROR:1,PARTIALLY_SCANNED:50};
  value.findings=[{kind:'PARTIALLY_SCANNED'}];
  assert.equal(presentation(value,1000).issues,4);
  assert.equal(presentation(value,1000).warnings,1);
  assert.match(presentation(value,1000).state,/failed/);
  value.active_run={...run(),state:'running'};
  assert.match(presentation(value,1000).state,/in progress/);
});
test('invalid schema, counts, runs, and paths rejected', () => {
  for(const change of [{schema_version:2},{file_counts:{CLEAN:-1}},{findings:[{path:5}]},
    {latest_scan:{}},{generated_at:NaN}]) assert.throws(()=>validate({...report(),...change}));
  const value=report();value.findings=[{kind:'YARA_MATCH',path:'/<script> ü.mkv',share_path:'//nas/<script> ü.mkv',time:900}];
  assert.equal(validate(value).findings[0].path,'/<script> ü.mkv');
});
test('duration displays seconds minutes and hours',()=>{
  assert.equal(formatDuration(12),'12s'); assert.equal(formatDuration(125),'2m 5s'); assert.equal(formatDuration(3661),'1h 1m');
});
