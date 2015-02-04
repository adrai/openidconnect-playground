'use strict';

// Grab the util module that's bundled with Node
var util = require('util');

// Create a new custom Error constructor
function InternalOAuthError(message, err) {
  // Pass the constructor to V8's
  // captureStackTrace to clean up the output
  Error.captureStackTrace(this, InternalOAuthError);

  this.message = message;
  this.oauthError = err;
}

// Extend our custom Error from Error
util.inherits(InternalOAuthError, Error);

// Give our custom error a name property. Helpful for logging the error later.
InternalOAuthError.prototype.name = InternalOAuthError.name;

InternalOAuthError.prototype.toString = function() {
  var m = this.message;
  if (this.oauthError) {
    if (this.oauthError instanceof Error) {
      m += ' (' + this.oauthError + ')';
    }
    else if (this.oauthError.statusCode && this.oauthError.data) {
      m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
    }
  }
  return m;
};

module.exports = InternalOAuthError;
