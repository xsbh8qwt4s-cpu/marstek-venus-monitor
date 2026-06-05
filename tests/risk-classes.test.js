// Unit tests for the BLE command risk classifier (safety overlay core).
// No deps — run with: node tests/risk-classes.test.js
// Verifies tier mapping + the fail-safe invariant (unknown code => DANGEROUS),
// which is what prevents an unrecognised/forged command from bypassing the gate.
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Load the browser IIFE in global scope so it assigns globalThis.MarstekRisk.
const src = fs.readFileSync(path.join(__dirname, '..', 'js', 'safety', 'risk-classes.js'), 'utf8');
(0, eval)(src);
const R = globalThis.MarstekRisk;
assert.ok(R && typeof R.classify === 'function', 'MarstekRisk.classify is present');
assert.deepStrictEqual(
  Object.keys(R.TIER).sort(),
  ['CONFIG', 'DANGEROUS', 'READ', 'SENSITIVE'],
  'four tiers exist',
);

// [code, expected tier, expected name?]
const known = [
  [0x03, 'READ', 'runtime_info'],
  [0x04, 'READ', 'device_info'],
  [0x10, 'READ', 'read_configuration'],
  [0x28, 'CONFIG', 'local_api_config'], // enable Local API — the headline use case
  [0x54, 'CONFIG', 'set_dod'],
  [0x21, 'CONFIG', 'meter_ip'],
  [0x09, 'CONFIG', 'set_work_mode'],
  [0x05, 'SENSITIVE', 'url_broker_config'], // cloud redirect
  [0x80, 'SENSITIVE', 'write_config'],
  [0x53, 'SENSITIVE', 'ble_lock'],
  [0x06, 'DANGEROUS', 'factory_reset'],
  [0x1f, 'DANGEROUS', 'fw_upgrade'],
  [0x1d, 'DANGEROUS', 'system_restart'],
  [0x0c, 'DANGEROUS', 'dev_mode_or_system_reset'],
];

let passed = 0;
for (const [code, tier, name] of known) {
  const r = R.classify(code);
  const hex = '0x' + code.toString(16).padStart(2, '0');
  assert.strictEqual(r.tier, tier, `${hex} tier => ${tier} (got ${r.tier})`);
  assert.strictEqual(r.known, true, `${hex} flagged known`);
  assert.strictEqual(r.name, name, `${hex} name => ${name} (got ${r.name})`);
  passed += 3;
}

// Fail-safe invariant: any code NOT in the table must classify DANGEROUS & known=false.
for (const code of [0x00, 0x01, 0x42, 0x99, 0xab, 0xff]) {
  const r = R.classify(code);
  const hex = '0x' + code.toString(16).padStart(2, '0');
  assert.strictEqual(r.tier, 'DANGEROUS', `unknown ${hex} must be DANGEROUS (fail-safe)`);
  assert.strictEqual(r.known, false, `unknown ${hex} must be known=false`);
  passed += 2;
}

console.log(`PASS risk-classes.test.js — ${passed} assertions (${known.length} known codes + 6 fail-safe)`);
