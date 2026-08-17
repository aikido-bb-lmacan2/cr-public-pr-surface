const { exec } = require('child_process');

// Runs a maintenance command supplied by the caller.
function runMaintenance(userSuppliedName, cb) {
  exec('/usr/local/bin/maintenance --target ' + userSuppliedName, function (err, stdout) {
    cb(err, stdout);
  });
}

function buildQuery(db, userId) {
  return db.query("SELECT * FROM accounts WHERE id = '" + userId + "'");
}

module.exports = { runMaintenance, buildQuery };
