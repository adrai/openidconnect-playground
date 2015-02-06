var exec = require('child_process').exec,
  async = require('async');

var client = {
  redirect_uris: [ 'http://localhost:3001/*' ],
  application_type: 'web',
  client_name: 'taibika-customer-app',
  token_endpoint_auth_method: 'client_secret_basic',
  client_secret: '123456789',
  trusted: 'true',
  _id: '110bb6e0-0bda-44f9-a724-dbe55176b8c0'
};

var user = {
  givenName: 'Hans',
  familyName: 'Muster',
  email: 'a@b.c',
  password: '123',
  _id: '327c06ef-caa2-455a-8687-541be74a214e'
};

function stringify (obj) {
  var json = JSON.stringify(obj);
  json = json.replace(/[\\]/g, '\\\\')
    .replace(/[\"]/g, '\\\"')
    .replace(/[\/]/g, '\\/')
    .replace(/[\b]/g, '\\b')
    .replace(/[\f]/g, '\\f')
    .replace(/[\n]/g, '\\n')
    .replace(/[\r]/g, '\\r')
    .replace(/[\t]/g, '\\t');
  return json;
}

module.exports = function (callback) {
  async.series([
    function (callback) {
      exec('cd ' + __dirname + ' && ./node_modules/anvil-connect/bin/nv migrate', callback);
    },
    function (callback) {
      exec('cd ' + __dirname + ' && ./node_modules/anvil-connect/bin/nv add client \"' + stringify(client) + '\"', function (err, infoout, errout) {
        console.log(infoout);
        console.log(errout);
        callback(err);
      });
    },
    function (callback) {
      exec('cd ' + __dirname + ' && ./node_modules/anvil-connect/bin/nv add user \"' + stringify(user) + '\"', function (err, infoout, errout) {
        console.log(infoout);
        console.log(errout);
        callback(err);
      });
    },
    function (callback) {
      exec('cd ' + __dirname + ' && ./node_modules/anvil-connect/bin/nv assign a@b.c authority', callback);
    }
  ], callback);
};
