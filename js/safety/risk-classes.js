// Marstek safety overlay — command risk classification.
// Mirrors the server-side audit sink (marstek_audit.py) so browser and bridge
// agree on tiers. Unknown codes are DANGEROUS (fail-safe). Tier map from RECON.md.
(function (global) {
  const TIER = { READ: 'READ', CONFIG: 'CONFIG', SENSITIVE: 'SENSITIVE', DANGEROUS: 'DANGEROUS' };
  const KNOWN = {
    // --- READ ---
    0x03: { name: 'runtime_info', tier: TIER.READ },
    0x04: { name: 'device_info', tier: TIER.READ },
    0x08: { name: 'wifi_info', tier: TIER.READ },
    0x0a: { name: 'settings_info', tier: TIER.READ },
    0x0d: { name: 'dev_mode_info', tier: TIER.READ },
    0x10: { name: 'read_configuration', tier: TIER.READ },
    0x13: { name: 'ble_event_log', tier: TIER.READ },
    0x14: { name: 'bms_data', tier: TIER.READ },
    0x1a: { name: 'hm_summary', tier: TIER.READ },
    0x1c: { name: 'hm_event_log', tier: TIER.READ },
    0x24: { name: 'network_info', tier: TIER.READ },
    0x51: { name: 'read_id_info', tier: TIER.READ },
    // --- CONFIG (settings writes) ---
    0x02: { name: 'set_server_type', tier: TIER.CONFIG },
    0x09: { name: 'set_work_mode', tier: TIER.CONFIG },
    0x0b: { name: 'set_datetime', tier: TIER.CONFIG },
    0x0e: { name: 'auto_mode_change', tier: TIER.CONFIG },
    0x0f: { name: 'backup_power', tier: TIER.CONFIG },
    0x15: { name: 'set_power_mode', tier: TIER.CONFIG },
    0x16: { name: 'set_ac_power', tier: TIER.CONFIG },
    0x17: { name: 'set_total_power', tier: TIER.CONFIG },
    0x19: { name: 'set_battery_mode', tier: TIER.CONFIG },
    0x20: { name: 'parallel_machine', tier: TIER.CONFIG },
    0x21: { name: 'meter_ip', tier: TIER.CONFIG },
    0x22: { name: 'ct_timing_profile', tier: TIER.CONFIG },
    0x23: { name: 'generator', tier: TIER.CONFIG },
    0x27: { name: 'power_array', tier: TIER.CONFIG },
    0x28: { name: 'local_api_config', tier: TIER.CONFIG },
    0x54: { name: 'set_dod', tier: TIER.CONFIG },
    // --- SENSITIVE (redirect / lock) ---
    0x05: { name: 'url_broker_config', tier: TIER.SENSITIVE },
    0x53: { name: 'ble_lock', tier: TIER.SENSITIVE },
    0x80: { name: 'write_config', tier: TIER.SENSITIVE },
    // --- DANGEROUS (reset / firmware) ---
    0x06: { name: 'factory_reset', tier: TIER.DANGEROUS },
    0x0c: { name: 'dev_mode_or_system_reset', tier: TIER.DANGEROUS },
    0x1d: { name: 'system_restart', tier: TIER.DANGEROUS },
    0x1f: { name: 'fw_upgrade', tier: TIER.DANGEROUS },
  };
  function classify(code, name) {
    const k = KNOWN[code];
    if (k) return { code, name: k.name, tier: k.tier, known: true };
    return { code, name: name || 'unknown', tier: TIER.DANGEROUS, known: false };
  }
  global.MarstekRisk = { TIER, classify };
})(typeof window !== 'undefined' ? window : globalThis);
