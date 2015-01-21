/**
 * Server Dependencies
 */

var fs                    = require('fs')
  , redis                 = require('redis')
  , client                = redis.createClient()
  , express               = require('express')
  , server                = express()
  , passport              = require('passport')
  // , OpenIDConnectStrategy = require('passport-openidconnect').Strategy
  , OpenIDConnectStrategy = require('./strategy')
  , cookieParser          = require('cookie-parser')
  , bodyParser            = require('body-parser')
  , session               = require('express-session')
  , RedisStore            = require('connect-redis')(session)
  , sessionStore          = new RedisStore({ client: client })
  ;



/**
 * Server configuration
 */

server.use(cookieParser('secret'));
server.use(bodyParser());
server.use(session({
  store:   sessionStore,
  secret: 'othersecret'
}));
server.use(passport.initialize());
server.use(passport.session());


// fake user database
var users = {};


/**
 * Serialize/deserialize user from session
 */

passport.serializeUser(function (user, done) {
  done(null, user.id);
});


passport.deserializeUser(function (id, done) {
  done(null, users[id] || null);
});


/**
 * Passport OpenID Connect Strategy
 */

var currentAccessToken;

var strat = new OpenIDConnectStrategy({
  authorizationURL: 'http://localhost:3000/authorize',
  tokenURL:         'http://localhost:3000/token',
  userInfoURL:      'http://localhost:3000/userinfo',
  clientID:         '110bb6e0-0bda-44f9-a724-dbe55176b8c0',
  clientSecret:     '123456789',
  callbackURL:      'http://localhost:3001/callback',
  scope:            ['profile']

}, function (iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) {
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
    strat.userProfile(currentAccessToken, function (err, profile) {
      console.log(arguments);
    });
    res.send('Logged in as ' + req.user._json.email + '. <a href="/signout">Signout</a>');
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
  res.redirect('/');
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
  console.log('ERROR', err)
  res.json(err);
})


/**
 * Start the server
 */

server.listen(3001);
console.log('client on port 3001');
