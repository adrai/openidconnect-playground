// /**
//  * Dependencies
//  */

// var cluster = require('cluster')
//   , os = require('os')
//   ;


// /**
//  * Fork the process for the number of CPUs available
//  */

// if (cluster.isMaster) {
//   var cpus = os.cpus().length;
//   console.log('Starting %s workers', cpus);
//   for (var i = 0; i < cpus; i += 1) {
//     cluster.fork();
//   }
// }


// /**
//  * Start the server in a worker
//  */

// else {
//   require('anvil-connect').start();
// }


// /**
//  * Replace dead workers
//  */

// cluster.on('exit', function (worker) {
//   cluster.fork();
// });

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
