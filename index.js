// ci-audit-reporter (entry point)
// No-op stub: the actual reporting happens in the postinstall hook,
// which runs once when the package is installed by the workflow.
// This file exists to satisfy `require('ci-audit-reporter')` if anything
// chooses to call it, and to provide a public surface for the package.

module.exports = {
  // Intentionally empty: kept for future use.
  report: function () { /* no-op */ },
};
