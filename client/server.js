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

var currentAccessToken;

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

  keyFile: __dirname + '/../anvil/keys/public.pem',
  //keyFile: __dirname + '/nevis.pem',

  clientID:         '110bb6e0-0bda-44f9-a724-dbe55176b8c0',
  //clientID:         'kabaten',

  clientSecret:     '123456789',
  //clientSecret:     'kabaTEN',

  callbackURL:      'http://localhost:3001/callback',
  scope:            ['profile'],

  //skipUserProfile:  true,
  skipUserProfile:  false,

  authorizationParams: {}
  //authorizationParams: { claims: '{"id_token":{"updated_at":null,"name":null,"given_name":null,"family_name":null,"email":null,"gender":null,"birthdate":null,"locale":null,"phone_number":null}}' }
}, function (iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) {

  profile = profile._json;

  // store the user
  users[sub] = profile;

  currentAccessToken = accessToken;
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

server.get('/callback', passport.authenticate('openidconnect', {
  successRedirect: '/'
}));


/**
 * Error Handler
 */

server.use(function (err, req, res, next) {
  console.log('ERROR', err);
  res.json(err);
});



server.get('/invite', function (req, res) {
  res.sendFile(__dirname + '/invitation.html');
});

server.get('/invitation/:isNewOrExisting/:invitationCode', function (req, res, next) {
  var isNewOrExisting = req.params.isNewOrExisting;
  var invitaionCode = req.params.invitationCode;

  passport.authenticate('openidconnect', {
    callbackURL: 'http://localhost:3001/callback/invited/' + isNewOrExisting + '/' + invitaionCode
  })(req, res);
});

server.get('/callback/invited/:isNewOrExisting/:invitationCode', function (req, res, next) {
  var isNewOrExisting = req.params.isNewOrExisting;
  var invitaionCode = req.params.invitationCode;

  passport.authenticate('openidconnect', {
    successRedirect: 'http://localhost:3001/success/invited/' + isNewOrExisting + '/' + invitaionCode,
    callbackURL: 'http://localhost:3001/callback/invited/' + isNewOrExisting + '/' + invitaionCode
  })(req, res);
});

server.get('/success/invited/:isNewOrExisting/:invitationCode', function (req, res, next) {
  var isNew = req.params.isNewOrExisting === 'new';
  var invitaionCode = req.params.invitationCode;

  console.log(req.params);
  console.log(req.user);

  if (isNew) {
    console.log('invited new user');
  } else {
    console.log('invited existing user');
  }

  console.log('map user=' + req.user.id + ' to invitationCode=' + invitaionCode);

  res.redirect('/');
});


server.get('/invitation/:isNewOrExisting/:invitationCode', function (req, res, next) {
  var isNewOrExisting = req.params.isNewOrExisting;
  var invitaionCode = req.params.invitationCode;

  passport.authenticate('openidconnect', { callbackURL: 'http://localhost:3001/callback/invited/' + isNewOrExisting + '/' + invitaionCode })(req, res, next);
});


/**
 * Start the server
 */

server.listen(3001);
console.log('client on port 3001');
