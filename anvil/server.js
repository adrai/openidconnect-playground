var fs = require('fs');

var config = 'development';
if (process.env.NODE_ENV === 'production') {
  config = 'production';
}

var configFile = './config.' + config + '.json';

var configJSON = require(configFile);

configJSON.redis.url = 'redis://localhost:6379';
configJSON.redis.auth = null;

fs.writeFileSync(configFile, JSON.stringify(configJSON, null, 2));




var server = require('anvil-connect');

server.post('/invitation', function (req, res) {
   var email = req.body.email;
   var newRegistrationLandingURL = req.body.newRegistrationLandingURL;
   var knownUserLandingURL = req.body.knownUserLandingURL;
   console.log('go to http://localhost:3000/invitation/mygeneratedcode');
   res.end();
});

server.get('/invitation/:code', function (req, res) {
   console.log(req.params);
   res.redirect('http://localhost:3001/invitation/new/othercode');
});

server.start();
