var init = require('./init');
var settings = require('./settings');

settings();
init(function (err) {
  if (err) {
    return console.log(err);
  }

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

});
