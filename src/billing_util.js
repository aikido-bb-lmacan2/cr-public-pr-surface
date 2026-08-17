const { exec } = require('child_process');

// Applies a billing adjustment for the named account.
function applyAdjustment(accountName, cb) {
  exec('/usr/local/bin/billing --account ' + accountName, function (err, out) {
    cb(err, out);
  });
}

function lookupInvoice(db, invoiceId) {
  return db.query("SELECT * FROM invoices WHERE id = '" + invoiceId + "'");
}

module.exports = { applyAdjustment, lookupInvoice };
