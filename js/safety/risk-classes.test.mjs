import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Load the browser script into a sandbox that exposes `window`.
const src = readFileSync(new URL('./risk-classes.js', import.meta.url), 'utf8');
const sandbox = { window: {} };
vm.runInNewContext(src, sandbox);
const { classify, TIER } = sandbox.window.MarstekRisk;

assert.equal(classify(0x14).tier, TIER.READ, 'bms_data is READ');
assert.equal(classify(0x14).name, 'bms_data');
assert.equal(classify(0x28).tier, TIER.CONFIG, '0x28 enable Local API is CONFIG');
assert.equal(classify(0x05).tier, TIER.SENSITIVE, '0x05 URL broker is SENSITIVE');
assert.equal(classify(0x06).tier, TIER.DANGEROUS, '0x06 factory reset is DANGEROUS');
assert.equal(classify(0x1f).tier, TIER.DANGEROUS, '0x1F fw upgrade is DANGEROUS');

const unknown = classify(0x99, 'mystery');
assert.equal(unknown.tier, TIER.DANGEROUS, 'unknown -> DANGEROUS (fail-safe)');
assert.equal(unknown.known, false);
assert.equal(unknown.name, 'mystery');

console.log('risk-classes: OK');
