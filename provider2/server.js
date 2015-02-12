'use strict';

/**
 * Module dependencies.
 */

var crypto = require('crypto'),
    express = require('express'),
    expressSession = require('express-session'),
    http = require('http'),
    path = require('path'),
    querystring = require('querystring'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    errorHandler = require('errorhandler'),
    repository = require('./lib/repository');

repository.init({ type: 'inmemory' }, function (err) {
  if (err) {
    return console.log(err);
  }

  var ownClients = [
    '110bb6e0-0bda-44f9-a724-dbe55176b8c0'
  ];

  var db = require('./lib/db');

  (function fillDbWithData() {
    var key = ownClients[0];
    db.clients.getByKey(key, function(err, client) {
      function addClient (usr) {
        var data = {
          name: 'ten',
          key: key,
          secret: '123456789'
        };
        db.clients.create(data, function(err, client){
          if(!err && client) {
            db.consents.create({
              user: usr.id,
              client: client.id,
              scopes: ['openid', 'profile']
            }, function (err, consent) {
              if(!err && consent) {
                console.log('db inited')
              } else {
                console.log(err);
              }
            });
          } else {
            console.log(err);
          }
        });
      }
      if(!err && !client) {
        db.users.getByEmail('a@b.c', function(err, user) {
          if (!user) {
            var data = {
              given_name: 'Hans',
              family_name: 'Muster',
              name: 'Hans Muster',
              email: 'a@b.c',
              password: '123',
              passConfirm: '123'
            };
            db.users.create(data, function(err, user) {
              addClient(user);
            });
          } else {
            addClient(user);
          }
        });
      }
    });
  })();

  var app = express();

  var options = {
    login_url: '/my/login',
    consent_url: '/user/consent',
    scopes: {
      foo: 'Access to foo special resource',
      bar: 'Access to bar special resource'
    }
  };

  var oidc = require('./lib/oidc')(options);

  // all environments
  app.set('port', process.env.PORT || 3000);
  app.use(bodyParser());
  app.use(cookieParser('Some Secret!!!'));
  app.use(expressSession({store: new expressSession.MemoryStore(), secret: 'Some Secret!!!', name: 'sessionKey', resave: true, saveUninitialized: true}));
  // app.use(app.router);

  //redirect to login
  app.get('/', function(req, res) {
    if (req.session.user) {
      res.redirect('/client');
    } else {
      res.redirect('/my/login');
    }
  });

  //Login form (I use email as user name)
  app.get('/my/login', function(req, res, next) {
    var head = '<head><title>Login</title></head>';
    var inputs = '<input type="text" name="email" placeholder="Enter Email"/><input type="password" name="password" placeholder="Enter Password"/>';
    var error = req.session.error?'<div>'+req.session.error+'</div>':'';
    var body = '<body><h1>Login</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
    res.send('<html>'+head+body+'</html>');
  });

  var validateUser = function (req, next) {
    delete req.session.error;
    db.users.getByEmail(req.body.email, function(err, user) {
      if(!err && user) {
        user.samePassword(req.body.password, function (err, same) {
          if (err) {
            return next(err);
          }
          if (same) {
            return next(null, user);
          } else {
            var error = new Error('Username or password incorrect.');
            return next(error);
          }
        });
      } else {
        var error = new Error('Username or password incorrect.');
        return next(error);
      }
    });
  };

  var afterLogin = function (req, res, next) {
    res.redirect(req.param('return_url')||'/user');
  };

  var loginError = function (err, req, res, next) {
    req.session.error = err.message;
    res.redirect(req.path);
  };

  app.post('/my/login', oidc.login(validateUser), afterLogin, loginError);


  app.all('/logout', oidc.removetokens(), function(req, res, next) {
    req.session.destroy();
    res.redirect('/my/login');
  });

  app.get('/signout', function(req, res, next) {
    req.session.destroy();
    res.redirect(req.query.redirect_uri);
  });

  app.all('/logout_forced', function(req, res, next) {
    req.session.destroy();
    res.redirect('/my/login');
  });

  //authorization endpoint
  app.get('/authorize', oidc.auth());

  //token endpoint
  app.post('/token', oidc.token());

  //user consent form
  app.get('/user/consent', oidc.loggedIn, function(req, res, next) {
    var head = '<head><title>Consent</title></head>';
    var lis = [];
    for(var i in req.session.scopes) {
      lis.push('<li><b>'+i+'</b>: '+req.session.scopes[i].explain+'</li>');
    }
    var ul = '<ul>'+lis.join('')+'</ul>';
    var error = req.session.error?'<div>'+req.session.error+'</div>':'';
    var body = '<body><h1>Consent</h1><form method="POST">'+ul+'<input type="submit" name="accept" value="Accept"/><input type="submit" name="cancel" value="Cancel"/></form>'+error;
    res.send('<html>'+head+body+'</html>');
  });

  //process user consent form
  app.post('/user/consent', oidc.consent());

  //user creation form
  app.get('/user/create', function(req, res, next) {
    var head = '<head><title>Sign in</title></head>';
    var inputs = '';
    //var fields = mkFields(oidc.model('user').attributes);
    var fields = {
      given_name: {
        label: 'Given Name',
        type: 'text'
      },
      middle_name: {
        label: 'Middle Name',
        type: 'text'
      },
      family_name: {
        label: 'Family Name',
        type: 'text'
      },
      email: {
        label: 'Email',
        type: 'email'
      },
      password: {
        label: 'Password',
        type: 'password'
      },
      passConfirm: {
        label: 'Confirm Password',
        type: 'password'
      }
    };
    for(var i in fields) {
      inputs += '<div><label for="'+i+'">'+fields[i].label+'</label><input type="'+fields[i].type+'" placeholder="'+fields[i].label+'" id="'+i+'"  name="'+i+'"/></div>';
    }
    var error = req.session.error?'<div>'+req.session.error+'</div>':'';
    var body = '<body><h1>Sign in</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
    res.send('<html>'+head+body+'</html>');
  });

  //process user creation
  app.post('/user/create', function(req, res, next) {
    delete req.session.error;
    db.users.getByEmail(req.body.email, function(err, user) {
      if(err) {
        req.session.error=err;
      } else if(user) {
        req.session.error='User already exists.';
      }
      if(req.session.error) {
        res.redirect(req.path);
      } else {
        req.body.name = req.body.given_name+' '+(req.body.middle_name?req.body.middle_name+' ':'')+req.body.family_name;
        db.users.create(req.body, function(err, user) {
          if(err || !user) {
            req.session.error=err?err:'User could not be created.';
            res.redirect(req.path);
          } else {
            db.clients.getByKey(ownClients[0], function (err, client) {
              db.consents.create({
                user: user.id,
                client: client.id,
                scopes: ['openid', 'profile']
              }, function (err, consent) {
                if(!err && consent) {
                  req.session.user = user.id;
                  res.redirect('/user');
                } else {
                  req.session.error=err?err:'Consent could not be created.';
                  res.redirect(req.path);
                }
              });
            });
          }
        });
      }
    });
  });

  app.get('/user', oidc.check(), function(req, res, next){
    res.send('<h1>User Page</h1><div><a href="/client">See registered clients of user</a></div>');
  });

  //User Info Endpoint
  app.get('/userinfo', oidc.userInfoByAccessToken());
  app.get('/api/userinfo', oidc.userInfo());

  app.get('/user/foo', oidc.check('foo'), function(req, res, next){
    res.send('<h1>Page Restricted by foo scope</h1>');
  });

  app.get('/user/bar', oidc.check('bar'), function(req, res, next){
    res.send('<h1>Page restricted by bar scope</h1>');
  });

  app.get('/user/and', oidc.check('bar', 'foo'), function(req, res, next){
    res.send('<h1>Page restricted by "bar and foo" scopes</h1>');
  });

  app.get('/user/or', oidc.check(/bar|foo/), function(req, res, next){
    res.send('<h1>Page restricted by "bar or foo" scopes</h1>');
  });

  //Client register form
  app.get('/client/register', function(req, res, next) {

    var mkId = function() {
      var key = crypto.createHash('md5').update(req.session.user+'-'+Math.random()).digest('hex');
      db.clients.getByKey(key, function(err, client) {
        if(!err && !client) {
          var secret = crypto.createHash('md5').update(key+req.session.user+Math.random()).digest('hex');
          req.session.register_client = {};
          req.session.register_client.key = key;
          req.session.register_client.secret = secret;
          var head = '<head><title>Register Client</title></head>';
          var inputs = '';
          var fields = {
            name: {
              label: 'Client Name',
              html: '<input type="text" id="name" name="name" placeholder="Client Name"/>'
            },
            redirect_uris: {
              label: 'Redirect Uri',
              html: '<input type="text" id="redirect_uris" name="redirect_uris" placeholder="Redirect Uri"/>'
            },
            key: {
              label: 'Client Key',
              html: '<span>'+key+'</span>'
            },
            secret: {
              label: 'Client Secret',
              html: '<span>'+secret+'</span>'
            }
          };
          for(var i in fields) {
            inputs += '<div><label for="'+i+'">'+fields[i].label+'</label> '+fields[i].html+'</div>';
          }
          var error = req.session.error?'<div>'+req.session.error+'</div>':'';
          var body = '<body><h1>Register Client</h1><form method="POST">'+inputs+'<input type="submit"/></form>'+error;
          res.send('<html>'+head+body+'</html>');
        } else if(!err) {
          mkId();
        } else {
          next(err);
        }
      });
    };
    mkId();
  });

  //process client register
  app.post('/client/register', function(req, res, next) {
    delete req.session.error;
    req.body.key = req.session.register_client.key;
    req.body.secret = req.session.register_client.secret;
    req.body.redirect_uris = req.body.redirect_uris.split(/[, ]+/);
    db.clients.create(req.body, function(err, client){
      if(!err && client) {
        db.consents.create({
          user:req.session.user,
          client: client.id
        }, function (err, consent) {
          if(!err && consent) {
            res.redirect('/client/'+client.id);
          } else {
            next(err);
          }
        });
      } else {
        next(err);
      }
    });
  });

  app.get('/client', oidc.loggedIn, function(req, res, next){
    var head ='<h1>Clients Page</h1><div><a href="/client/register"/>Register new client</a></div>';
    db.clients.findByUser(req.session.user, function(err, clients){
      var body = ["<ul>"];
      clients.forEach(function(client) {
        body.push('<li><a href="/client/'+client.id+'">'+client.name+'</li>');
      });
      body.push('</ul>');
      res.send(head+body.join(''));
    });
  });

  app.get('/client/:id', function(req, res, next){
    db.clients.getById(req.params.id, function(err, client){
      if(err) {
        next(err);
      } else if(client) {
        var html = '<h1>Client '+client.name+' Page</h1><div><a href="/client">Go back</a></div><ul><li>Key: '+client.key+'</li><li>Secret: '+client.secret+'</li><li>Redirect Uris: <ul>';
        client.redirect_uris.forEach(function(uri){
          html += '<li>'+uri+'</li>';
        });
        html+='</ul></li></ul>';
        res.send(html);
      } else {
        res.send('<h1>No Client Fount!</h1><div><a href="/client">Go back</a></div>');
      }
    });
  });

  // development only
  if ('development' == app.get('env')) {
    app.use(errorHandler());
  }

  http.createServer(app).listen(app.get('port'), function(){
    console.log('Express server listening on port ' + app.get('port'));
  });
});