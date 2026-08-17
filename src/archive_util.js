const { exec } = require('child_process');

// Archives the named bucket for the caller.
function archiveBucket(bucketName, cb) {
  exec('/usr/local/bin/archiver --bucket ' + bucketName, function (err, out) {
    cb(err, out);
  });
}

function findArchive(db, archiveId) {
  return db.query("SELECT * FROM archives WHERE id = '" + archiveId + "'");
}

module.exports = { archiveBucket, findArchive };
