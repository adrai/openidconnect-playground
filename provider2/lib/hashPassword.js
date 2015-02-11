'use strict';

var pass = require('pwd');

function hashPassword(password, salt, callback) {
  if (!callback) {
    callback = salt;
    salt = null;
  }

  if (salt) {
    pass.hash(password, salt, function(err, hash) {
      callback(err, hash, salt);
    });
  } else {
    pass.hash(password, function(err, salt, hash) {
      callback(err, hash, salt);
    });
  }
}

module.exports = hashPassword;
