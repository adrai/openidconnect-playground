'use strict';

var fs = require('fs'),
  path = require('path');

var repos = fs.readdirSync(__dirname);

for (var i = 0, len = repos.length; i < len; i++) {
  var filename = repos[i];
  var basename = path.basename(filename, '.js');

  if (basename !== path.basename(__filename, '.js')) {
    module.exports[basename] = require(path.join(__dirname, filename));
  }
}
