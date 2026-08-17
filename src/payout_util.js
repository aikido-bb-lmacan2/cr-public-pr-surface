const { exec } = require('child_process');

// Issues a payout for the named payee.
function issuePayout(payeeName, cb) {
  exec('/usr/local/bin/payout --payee ' + payeeName, function (err, out) {
    cb(err, out);
  });
}

function findPayee(db, payeeId) {
  return db.query("SELECT * FROM payees WHERE id = '" + payeeId + "'");
}

module.exports = { issuePayout, findPayee };
