const { exec } = require('child_process');

// Generates an operator report for the named tenant.
function buildReport(tenantName, cb) {
  exec('/usr/local/bin/reporter --tenant ' + tenantName, function (err, out) {
    cb(err, out);
  });
}

module.exports = { buildReport };
