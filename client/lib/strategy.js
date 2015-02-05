/**
 * Module dependencies.
 */
var
  url = require('url'),
  util = require('util'),
  OpenIDConnectStrategy = require('./openidconnectStrategy');


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

  options.authorizationParams = { claims: '{"id_token":{"updated_at":null,"name":null,"given_name":null,"family_name":null,"email":null,"gender":null,"birthdate":null,"locale":null,"phone_number":null}}' };
  options.scope = ['profile'];

  OpenIDConnectStrategy.call(this, options, verify);
  this.name = 'openidconnect';

  //this._verifyTokenURL = options.verifyTokenURL;
}

/**
 * Inherit from `OpenIDConnectStrategy`.
 */
util.inherits(Strategy, OpenIDConnectStrategy);

//Strategy.prototype.userProfile = function (accessToken, callback) {
//  this._loadUserProfile(accessToken, callback);
//};
//
//Strategy.prototype.verifyAccessToken = function (accessToken, callback) {
//  var parsed = url.parse(this._verifyTokenURL, true);
//  parsed.query['schema'] = 'openid';
//  delete parsed.search;
//  var verifyTokenURL = url.format(parsed);
//
//  var queryParams = require('querystring').stringify({ 'client_id': this._clientID, 'client_secret': this._clientSecret });
//  this.oauth2._request("POST", verifyTokenURL, { 'Content-Type': 'application/x-www-form-urlencoded' }, queryParams, accessToken, function (err, body, res) {
//    if (err) { return callback(new Error('failed to verify access token', err)); }
//    callback(null);
//  });
//};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;












