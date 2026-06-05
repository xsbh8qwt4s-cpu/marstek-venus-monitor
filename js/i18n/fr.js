// French labels for the safety overlay (added features only; upstream stays EN).
(function (global) {
  global.MarstekFR = {
    riskLine: (tier, name, code) =>
      `Commande ${name} (0x${code.toString(16).toUpperCase().padStart(2, '0')}) — niveau ${tier}.`,
    proceed: 'Confirmer ?',
    dangerWarn:
      'Opération DANGEREUSE (peut endommager / bloquer / réinitialiser l’appareil). ' +
      'Tape le jeton de validation pour continuer.',
    tokenPrompt: 'Jeton de validation (2FA manuel) :',
    cancelled: 'Opération annulée.',
  };
})(typeof window !== 'undefined' ? window : globalThis);
