var fs = require('fs');

module.exports = function () {
  var config = 'development';
  if (process.env.NODE_ENV === 'production') {
    config = 'production';
  }

  var configFile = './config.' + config + '.json';

  var configJSON = require(configFile);

  configJSON.redis.url = 'redis://localhost:6379';
  configJSON.redis.auth = null;

  fs.writeFileSync(configFile, JSON.stringify(configJSON, null, 2));
};
