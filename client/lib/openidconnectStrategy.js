/**
 * Based on: https://github.com/jaredhanson/passport-openidconnect/blob/master/lib/strategy.js
 */

'use strict';

/**
 * Module dependencies.
 */
var
  passport = require('passport'),
  url = require('url'),
  querystring= require('querystring'),
  util = require('util'),
  OAuth2 = require('oauth').OAuth2,
  crypto = require('crypto'),
  jsjws = require('jsjws'),
  fs = require('fs'),
  InternalOAuthError = require('./internalOAuthError');

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
function originalURL(req) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] == 'https')
      ? 'https'
      : 'http'
    , host = headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
}

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * CREDIT: Connect -- utils.uid
 *         https://github.com/senchalabs/connect/blob/2.7.2/lib/utils.js
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */
function uid (len) {
  return crypto.randomBytes(Math.ceil(len * 3 / 4))
    .toString('base64')
    .slice(0, len);
}

function Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;

  if (!options.authorizationURL) throw new Error('OpenIDConnectStrategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OpenIDConnectStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OpenIDConnectStrategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OpenIDConnectStrategy requires a clientSecret option');

  this._authorizationURL = options.authorizationURL;
  this._tokenURL = options.tokenURL;
  this._userInfoURL = options.userInfoURL;

  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
  this._callbackURL = options.callbackURL;

  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  if (typeof this._skipUserProfile !== 'function') {
    if (this._skipUserProfile) {
      this._skipUserProfile = function (issuer, subject, callback) { callback(null, true); }
    } else {
      this._skipUserProfile = function (issuer, subject, callback) { callback(null, false); }
    }
  }

  this._authorizationParams = options.authorizationParams || {};

  this.oauth2 = new OAuth2(this._clientID,  this._clientSecret, '', this._authorizationURL, this._tokenURL);

  this._keyFile = options.keyFile || null;
  this.key = null;

  if (this._keyFile) {
    this.loadKey(this._keyFile);
  }

  if (!this.key) {
    console.log('Are you sure to not verify the signature?');
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


Strategy.prototype.loadKey = function(url) {
  this.key = fs.readFileSync(url, {encoding: 'utf8'});
  if (this.key.indexOf('-----BEGIN CERTIFICATE-----') >= 0) {
    this.key = jsjws.X509.getPublicKeyFromCertPEM(this.key);
  } else {
    this.key = jsjws.createPublicKey(this.key, 'utf8');
  }
};

Strategy.prototype.verifySignature = function (idToken) {
  var jws = new jsjws.JWS();
  var err = null;
  try {
    if (!jws.verifyJWSByKey(idToken, this.key)) {
      err = new Error('Signature verification failed');
    }
  }
  catch (e) {
    err = new Error('Bad signature');
  }
  if (err) {
    throw err;
  }
};

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    return this.fail();
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(originalURL(req), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    this.oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
      if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

      //console.log('TOKEN');
      //console.log('AT: ' + accessToken);
      //console.log('RT: ' + refreshToken);
      //console.log(params);
      //console.log('----');

      var idToken = params['id_token'];
      if (!idToken) { return self.error(new Error('ID Token not present in token response')); }

      var idTokenSegments = idToken.split('.')
        , jwtClaimsStr
        , jwtClaims;

      if (self.key) {
        var errored = false;
        try {
          self.verifySignature(idToken);
        }
        catch (e) {
          self.error(e);
          errored = true;
        }
        if (errored) {
          return;
        }
      }

      try {
        jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
        jwtClaims = JSON.parse(jwtClaimsStr);
      } catch (ex) {
        return self.error(ex);
      }

      var iss = jwtClaims.iss;
      var sub = jwtClaims.sub;
      // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
      // "sub" claim was named "user_id".  Many providers still issue the
      // claim under the old field, so fallback to that.
      if (!sub) {
        sub = jwtClaims.user_id;
      }

      // NOTE: Ensure claims are validated per:
      //       http://openid.net/specs/openid-connect-basic-1_0.html#id_token


      self._shouldLoadUserProfile(iss, sub, function(err, load) {
        if (err) { return self.error(err); }

        function onProfileLoaded(profile) {
          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 10) {
              self._verify(req, iss, sub, profile, jwtClaims, idToken, accessToken, refreshToken, params, verified);
            } else if (arity == 9) {
              self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity == 8) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity == 7) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity == 5) {
              self._verify(req, iss, sub, profile, verified);
            } else { // arity == 4
              self._verify(req, iss, sub, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 9) {
              self._verify(iss, sub, profile, jwtClaims, idToken, accessToken, refreshToken, params, verified);
            } else if (arity == 8) {
              self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity == 7) {
              self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity == 6) {
              self._verify(iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity == 4) {
              self._verify(iss, sub, profile, verified);
            } else { // arity == 3
              self._verify(iss, sub, verified);
            }
          }
        }

        self._loadUserProfile(load ? accessToken : false, jwtClaims, function (err, prof) {
          if (err) {
            return self.error(err);
          }
          onProfileLoaded(prof);
        });
      });
    });
  } else {
    var params = this.authorizationParams(options) || {};
    //var params = {};
    params['response_type'] = 'code';
    params['client_id'] = this._clientID;
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
    if (scope) {
      params.scope = 'openid' + this._scopeSeparator + scope;
    } else {
      params.scope = 'openid';
    }

    //var state = options.state;
    //if (state) { params.state = state; }

    var state = uid(16);

    var location = this._authorizationURL + '?' + querystring.stringify(params);
    this.redirect(location);
  }
};

Strategy.prototype._loadUserProfile = function(load, jwtClaims, callback) {
  var self = this;

  var accessToken = null;

  if (typeof load === 'string') {
    accessToken = load;
    load = true;
  }

  if (typeof jwtClaims === 'function') {
    callback = jwtClaims;
    jwtClaims = null;
  }

  var profile;

  if (load) {
    var parsed = url.parse(this._userInfoURL, true);
    parsed.query['schema'] = 'openid';
    delete parsed.search;
    var userInfoURL = url.format(parsed);

    // NOTE: We are calling node-oauth's internal `_request` function (as
    //       opposed to `get`) in order to send the access token in the
    //       `Authorization` header rather than as a query parameter.
    //
    //       Additionally, the master branch of node-oauth (as of
    //       2013-02-16) will include the access token in *both* headers
    //       and query parameters, which is a violation of the spec.
    //       Setting the fifth argument of `_request` to `null` works
    //       around this issue.

    //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
    this.oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
      if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }

      profile = {};

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
        profile._json.id = profile.id;

        callback(null, profile);
      } catch(e) {
        return callback(e);
      }
    });
  } else if (jwtClaims) {
    profile = {};
    profile.id = jwtClaims.sub || jwtClaims.user_id;

    profile.displayName = jwtClaims.name;
    profile.name = { familyName: jwtClaims.family_name,
      givenName: jwtClaims.given_name,
      middleName: jwtClaims.middle_name };

    profile._raw = JSON.stringify(jwtClaims);
    profile._json = JSON.parse(profile._raw);
    profile._json.id = profile.id;

    var toRemove = ['sub', 'aud', 'exp', 'iat', 'iss'];

    toRemove.forEach(function (prop) {
      if (profile._json[prop]) {
        delete profile._json[prop];
      }
    });

    callback(null, profile);
  } else {
    callback(null);
  }
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return this._authorizationParams;
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 2) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
