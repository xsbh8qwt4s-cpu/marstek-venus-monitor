// Safety gate + audit client, wired into ble-protocol.js send paths.
// beforeSend: classify -> (confirm if not READ) -> POST /audit -> allow/deny.
// Same-origin /audit works when served by the P0a bridge (http://localhost).
// deviceName is passed by the hook (the send fns share scope with `device`).
(function (global) {
  const AUDIT_URL = '/audit';

  async function postAudit(rec) {
    try {
      const res = await fetch(AUDIT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rec),
      });
      return await res.json();
    } catch (e) {
      // Bridge absent (e.g. GitHub Pages): keep an in-page trail, never block reads.
      (global.__marstekAuditFallback ||= []).push(rec);
      console.warn('[MarstekSafety] audit bridge unreachable; recorded in-page only', e);
      return null;
    }
  }

  function record(commandType, commandName, payload, result, token, deviceName) {
    return postAudit({
      device: deviceName || 'unknown',
      command_code: commandType,
      command_name: commandName,
      // Never log raw payload bytes (may carry config secrets) — length only.
      params: payload ? { payload_len: payload.length } : {},
      result: result,
      confirm_token: token,
    });
  }

  async function beforeSend(commandType, commandName, payload, deviceName) {
    const spec = global.MarstekRisk.classify(commandType, commandName);
    let token = null;
    if (spec.tier !== global.MarstekRisk.TIER.READ) {
      const decision = await global.MarstekConfirm.ask(spec);
      if (!decision.ok) return false;
      token = decision.token || null;
    }
    await record(commandType, commandName, payload, 'sent', token, deviceName);
    return true;
  }

  function afterSend(commandType, commandName, outcome, deviceName) {
    const spec = global.MarstekRisk.classify(commandType, commandName);
    // Reads that succeed stay quiet (avoid log spam); record writes + any failure.
    if (spec.tier === global.MarstekRisk.TIER.READ && outcome.ok) return;
    record(
      commandType,
      commandName,
      null,
      outcome.ok ? 'ok' : `error:${outcome.error || 'unknown'}`,
      null,
      deviceName
    );
  }

  global.MarstekSafety = { beforeSend, afterSend };
})(typeof window !== 'undefined' ? window : globalThis);
