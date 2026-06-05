// Confirm dialogs for the safety overlay. Returns Promise<{ok, token}>.
// READ -> caller skips this. CONFIG -> single confirm.
// SENSITIVE/DANGEROUS -> confirm + typed validation token (manual 2FA, CLAUDE.md #4).
(function (global) {
  const T = global.MarstekRisk.TIER;
  function ask(spec) {
    const L = global.MarstekFR;
    const msg = L.riskLine(spec.tier, spec.name, spec.code);
    if (spec.tier === T.CONFIG) {
      return Promise.resolve({ ok: global.confirm(`${msg}\n\n${L.proceed}`) });
    }
    // SENSITIVE or DANGEROUS: confirm, then require a non-empty typed token.
    if (!global.confirm(`${msg}\n\n${L.dangerWarn}`)) {
      return Promise.resolve({ ok: false });
    }
    const token = global.prompt(L.tokenPrompt, '');
    if (!token) {
      global.alert(L.cancelled);
      return Promise.resolve({ ok: false });
    }
    return Promise.resolve({ ok: true, token });
  }
  global.MarstekConfirm = { ask };
})(typeof window !== 'undefined' ? window : globalThis);
