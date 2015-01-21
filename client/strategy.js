/**
 * Module dependencies.
 */
var util = require('util')
  , OpenIDConnectStrategy = require('passport-openidconnect').Strategy
  , OAuth2 = require('oauth').OAuth2;


/**
 * `Strategy` constructor.
 *
 * The PayPal authentication strategy authenticates requests by delegating to
 * PayPal using the OpenID Connect protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your application's App ID
 *   - `clientSecret`  your application's App Secret
 *   - `callbackURL`   URL to which PayPal will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new PayPalStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/paypal/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  // this.profileURL = options.profileURL || 'https://identity.x.com/xidentity/resources/profile/me';
  options = options || {};

  if (!options.authorizationURL) throw new Error('OpenIDConnectStrategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OpenIDConnectStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OpenIDConnectStrategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OpenIDConnectStrategy requires a clientSecret option');

  OpenIDConnectStrategy.call(this, options, verify);
  this.name = 'openidconnect';

  // this._oauth2.setAccessTokenName("oauth_token");
}

/**
 * Inherit from `OpenIDConnectStrategy`.
 */
util.inherits(Strategy, OpenIDConnectStrategy);

Strategy.prototype.userProfile = function (accessToken, callback) {
  var self = this;
  var oauth2 = new OAuth2(this._clientID,  this._clientSecret,
                            '', this._authorizationURL, this._tokenURL);
  oauth2._request("GET", this._userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
    if (err) {
      return callback(err);
    }
    
    console.log('PROFILE');
    console.log(body);
    console.log('-------');
    
    var profile = {};
    
    try {
      var json = JSON.parse(body);
      
      profile.id = json.sub;
      // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
      // "sub" key was named "user_id".  Many providers still use the old
      // key, so fallback to that.
      if (!profile.id) {
        profile.id = json.user_id;
      }
      
      profile.displayName = json.name;
      profile.name = { familyName: json.family_name,
                       givenName: json.given_name,
                       middleName: json.middle_name };
      
      profile._raw = body;
      profile._json = json;
      
      callback(null, profile);
    } catch(e) {
      self.error(e);
      return callback(e);
    }
  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
