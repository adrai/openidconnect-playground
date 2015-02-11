/**
 * Server Dependencies
 */

var fs                    = require('fs')
  , express               = require('express')
  , server                = express()
  , passport              = require('passport')
  // , OpenIDConnectStrategy = require('passport-openidconnect').Strategy
  , OpenIDConnectStrategy = require('./lib/strategy')
  , cookieParser          = require('cookie-parser')
  , bodyParser            = require('body-parser')
  , session               = require('express-session')
  , MemoryStore           = session.MemoryStore
  , sessionStore          = new MemoryStore()
  ;



/**
 * Server configuration
 */

server.use(cookieParser('secret'));
server.use(bodyParser());
server.use(session({
  store: sessionStore,
  secret: 'secret',
  key: 'express.sid'
}));
server.use(passport.initialize());
server.use(passport.session());


// fake user database
var users = {};


/**
 * Serialize/deserialize user from session
 */

passport.serializeUser(function (user, done) {
  done(null, user);
});


passport.deserializeUser(function (user, done) {
  done(null, users[user.id] || null);
});


/**
 * Passport OpenID Connect Strategy
 */


// only for testing
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

var logoutUrl = 'http://localhost:3000/signout?redirect_uri=http://localhost:3001';
//var logoutUrl = 'https://kbrs105217/ten/authorize?logout&redirect_uri=http://localhost:3001';

var strat = new OpenIDConnectStrategy({
  authorizationURL: 'http://localhost:3000/authorize',
  //authorizationURL: 'https://kbrs105217/ten/authorize',

  tokenURL:         'http://localhost:3000/token',
  //tokenURL:         'https://kbrs105217/ten/authorize',

  userInfoURL:      'http://localhost:3000/userinfo',

  //keyFile: __dirname + '/../anvil/keys/public.pem',
  //keyFile: __dirname + '/nevis.pem',

  clientID:         '110bb6e0-0bda-44f9-a724-dbe55176b8c0',
  //clientID:         'kabaten',

  clientSecret:     '123456789',
  //clientSecret:     'kabaTEN',

  callbackURL:      'http://localhost:3001/callback',

  //skipUserProfile:  true,
  skipUserProfile:  false
}, function (iss, sub, profile, jwtClaims, idToken, accessToken, refreshToken, params, done) {

  console.log('idToken to pass to DAAL: ' + idToken);

  profile = profile._json;

  // store the user
  users[sub] = profile;

  var invitationCode = params.state;
  if (invitationCode) {
    console.log('map user=' + profile.id + ' to invitationCode=' + invitationCode);
  }

  done(null, profile);
});

passport.use(strat);


/**
 * View with signin link
 */

server.get('/', function (req, res) {
  if (req.user) {
    if (!req.user.email) {
      return res.send('Logged in as ' + req.user.id + '. <a href="/signout">Signout</a>');
    }

    res.send('Logged in as ' + req.user.given_name + ' ' + req.user.family_name + ' (' + req.user.email + '). <a href="/signout">Signout</a>');
  } else {
    res.send('<a href="/signin">Signin</a>');
  }
});

/**
 * Passport authenticate route
 */

server.get('/signin', passport.authenticate('openidconnect'));

/**
 * Sign out
 */

server.get('/signout', function (req, res, next) {
  req.logout();
  res.redirect(logoutUrl);
});

/**
 * Handle Anvil Connect Auth Flow Response
 */

//server.get('/callback', passport.authenticate('openidconnect', {
//  successRedirect: '/',
//  failureRedirect: '/fail'
//}));

server.get('/callback', function (req, res, next) {
  passport.authenticate('openidconnect', {
    successRedirect: '/',
    failureRedirect: '/fail',
    state: req.query.state
  })(req, res, next);
});


/**
 * Error Handler
 */

server.use(function (err, req, res, next) {
  console.log('ERROR', err);
  console.log(err.stack);
  res.json(err);
});



server.get('/invite', function (req, res) {
  res.sendFile(__dirname + '/invitation.html');
});

server.get('/invitation/:isNewOrExisting/:invitationCode', function (req, res, next) {
  var isNewOrExisting = req.params.isNewOrExisting;
  var invitaionCode = req.params.invitationCode;

  //passport.authenticate('openidconnect', {
  //  callbackURL: 'http://localhost:3001/callback/invited/' + isNewOrExisting + '/' + invitaionCode
  //})(req, res);

  passport.authenticate('openidconnect', {
    state: invitaionCode
  })(req, res);
});

//server.get('/callback/invited/:isNewOrExisting/:invitationCode', function (req, res, next) {
//  var isNewOrExisting = req.params.isNewOrExisting;
//  var invitaionCode = req.params.invitationCode;
//
//  passport.authenticate('openidconnect', {
//    failureRedirect: '/fail',
//    successRedirect: 'http://localhost:3001/success/invited/' + isNewOrExisting + '/' + invitaionCode,
//    callbackURL: 'http://localhost:3001/callback/invited/' + isNewOrExisting + '/' + invitaionCode,
//    state: req.query.state
//  })(req, res);
//});

//server.get('/success/invited/:isNewOrExisting/:invitationCode', function (req, res, next) {
//  var isNew = req.params.isNewOrExisting === 'new';
//  var invitaionCode = req.params.invitationCode;
//
//  if (isNew) {
//    console.log('invited new user');
//  } else {
//    console.log('invited existing user');
//  }
//
//  console.log('map user=' + req.user.id + ' to invitationCode=' + invitaionCode);
//
//  res.redirect('/');
//});


/**
 * Start the server
 */

server.listen(3001);
console.log('client on port 3001');
