var querystring = require('querystring'),
  crypto = require('crypto'),
  _ = require('lodash'),
  extend = require('extend'),
  url = require('url'),
  Q = require('q'),
  jwt = require('jwt-simple'),
  util = require("util"),
  base64url = require('base64url'),
  db = require('./db');

var defaults = {
  login_url: '/login',
  consent_url: '/consent',
  scopes: {
    openid: 'Informs the Authorization Server that the Client is making an OpenID Connect request.',
    profile: 'Access to the End-User\'s default profile Claims.',
    email: 'Access to the email and email_verified Claims.',
    address: 'Access to the address Claim.',
    phone: 'Access to the phone_number and phone_number_verified Claims.',
    offline_access: 'Grants access to the End-User\'s UserInfo Endpoint even when the End-User is not present (not logged in).'
  }
};

function parse_authorization(authorization) {
  if (!authorization) {
    return null;
  }

  var parts = authorization.split(' ');

  if (parts.length != 2 || parts[0] != 'Basic') {
    return null;
  }

  var creds = new Buffer(parts[1], 'base64').toString(),
    i = creds.indexOf(':');

  if (i == -1)
    return null;

  var username = creds.slice(0, i);
  var password = creds.slice(i + 1);

  return [username, password];
}

function OpenIDConnect(options) {
  this.settings = extend(true, {}, defaults, options);

  var self = this;
  this.settings.policies = {
    loggedIn: function (req, res, next) {
      if (req.session.user) {
        next();
      } else {
        var q = req.parsedParams ? req.path + '?' + querystring.stringify(req.parsedParams) : req.originalUrl;
        res.redirect(self.settings.login_url + '?' + querystring.stringify({return_url: q}));
      }
    }
  };
}

OpenIDConnect.prototype.errorHandle = function (res, uri, error, desc) {
  if (uri) {
    var redirect = url.parse(uri, true);
    redirect.query.error = error; //'invalid_request';
    redirect.query.error_description = desc; //'Parameter '+x+' is mandatory.';
    res.redirect(400, url.format(redirect));
  } else {
    res.send(400, error + ': ' + desc);
  }
};

OpenIDConnect.prototype.endpointParams = function (spec, req, res, next) {
  try {
    req.parsedParams = this.parseParams(req, res, spec);
    next();
  } catch (err) {
    this.errorHandle(res, err.uri, err.error, err.msg);
  }
};

OpenIDConnect.prototype.parseParams = function (req, res, spec) {
  var params = {};
  var r = req.param('redirect_uri');
  for (var i in spec) {
    var x = req.param(i);
    if (x) {
      params[i] = x;
    }
  }

  for (var i in spec) {
    var x = params[i];
    if (!x) {
      var error = false;
      if (typeof spec[i] == 'boolean') {
        error = spec[i];
      } else if (_.isPlainObject(spec[i])) {
        for (var j in spec[i]) {
          if (!util.isArray(spec[i][j])) {
            spec[i][j] = [spec[i][j]];
          }
          spec[i][j].forEach(function (e) {
            if (!error) {
              if (util.isRegExp(e)) {
                error = e.test(params[j]);
              } else {
                error = e == params[j];
              }
            }
          });
        }
      } else if (_.isFunction(spec[i])) {
        error = spec[i](params);
      }

      if (error) {
        throw {type: 'error', uri: r, error: 'invalid_request', msg: 'Parameter ' + i + ' is mandatory.'};
        //this.errorHandle(res, r, 'invalid_request', 'Parameter '+i+' is mandatory.');
        //return;
      }
    }
  }
  return params;
};

/**
 * login
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.post('/login', oidc.login(),  afterLogin, loginErrorHandler);
 *
 * This calls verification strategy and creates session.
 * Verification strategy must have two parameters: req and callback function with two parameters: error and user
 *
 *
 */
OpenIDConnect.prototype.login = function (validateUser) {
  return [
    function (req, res, next) {
      validateUser(req, /*next:*/function (error, user) {
        if (!error && !user) {
          error = new Error('User not validated');
        }
        if (!error) {
          if (user.id) {
            req.session.user = user.id;
          } else {
            delete req.session.user;
          }
          if (user.sub) {
            if (typeof user.sub === 'function') {
              req.session.sub = user.sub();
            } else {
              req.session.sub = user.sub;
            }
          } else {
            delete req.session.sub;
          }
          return next();
        } else {
          return next(error);
        }
      });
    }
  ];
};

/**
 * auth
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/authorization', oidc.auth());
 *
 * This is the authorization endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.1
 *
 */
OpenIDConnect.prototype.auth = function () {
  var self = this;
  var spec = {
    response_type: true,
    client_id: true,
    scope: true,
    redirect_uri: true,
    state: false,
    nonce: function (params) {
      return params.response_type.indexOf('id_token') !== -1;
    },
    display: false,
    prompt: false,
    max_age: false,
    ui_locales: false,
    claims_locales: false,
    id_token_hint: false,
    login_hint: false,
    acr_values: false,
    response_mode: false
  };
  return [
    function (req, res, next) {
      self.endpointParams(spec, req, res, next);
    },
    this.settings.policies.loggedIn,
    function (req, res, next) {
      Q(req.parsedParams).then(function (params) {
        //Step 2: Check if response_type is supported and client_id is valid.

        var deferred = Q.defer();
        switch (params.response_type) {
          case 'none':
          case 'code':
          case 'token':
          case 'id_token':
            break;
          default:
            //var error = false;
            var sp = params.response_type.split(' ');
            sp.forEach(function (response_type) {
              if (['code', 'token', 'id_token'].indexOf(response_type) == -1) {
                throw {
                  type: 'error',
                  uri: params.redirect_uri,
                  error: 'unsupported_response_type',
                  msg: 'Response type ' + response_type + ' not supported.'
                };
              }
            });
        }
        db.clients.getByKey(params.client_id, function (err, model) {
          if (err || !model || model === '') {
            deferred.reject({
              type: 'error',
              uri: params.redirect_uri,
              error: 'invalid_client',
              msg: 'Client ' + params.client_id + ' doesn\'t exist.'
            });
          } else {
            req.session.client_id = model.id;
            req.session.client_secret = model.secret;
            deferred.resolve(params);
          }
        });

        return deferred.promise;
      }).then(function (params) {
        //Step 3: Check if scopes are valid, and if consent was given.

        var deferred = Q.defer();
        var reqsco = params.scope.split(' ');
        req.session.scopes = {};
        var promises = [];
        db.consents.getByUserAndClient(req.session.user, req.session.client_id, function (err, consent) {
          reqsco.forEach(function (scope) {
            var innerDef = Q.defer();
            if (!self.settings.scopes[scope]) {
              innerDef.reject({
                type: 'error',
                uri: params.redirect_uri,
                error: 'invalid_scope',
                msg: 'Scope ' + scope + ' not supported.'
              });
            }
            if (!consent) {
              req.session.scopes[scope] = {ismember: false, explain: self.settings.scopes[scope]};
              innerDef.resolve(true);
            } else {
              var inScope = consent.scopes.indexOf(scope) !== -1;
              req.session.scopes[scope] = {ismember: inScope, explain: self.settings.scopes[scope]};
              innerDef.resolve(!inScope);
            }
            promises.push(innerDef.promise);
          });

          Q.allSettled(promises).then(function (results) {
            var redirect = false;
            for (var i = 0; i < results.length; i++) {
              if (results[i].value) {
                redirect = true;
                break;
              }
            }
            if (redirect) {
              req.session.client_key = params.client_id;
              var q = req.path + '?' + querystring.stringify(params);
              deferred.reject({
                type: 'redirect',
                uri: self.settings.consent_url + '?' + querystring.stringify({return_url: q})
              });
            } else {
              deferred.resolve(params);
            }
          });
        });

        return deferred.promise;
      }).then(function (params) {
        //Step 5: create responses
        if (params.response_type == 'none') {
          return {params: params, resp: {}};
        } else {
          var deferred = Q.defer();
          var promises = [];

          var rts = params.response_type.split(' ');

          rts.forEach(function (rt) {
            var def = Q.defer();
            promises.push(def.promise);
            switch (rt) {
              case 'code':
                var createToken = function () {
                  var token = crypto.createHash('md5').update(params.client_id).update(Math.random() + '').digest('hex');
                  db.auths.getByCode(token, function (err, auth) {
                    if (!auth) {
                      setToken(token);
                    } else {
                      createToken();
                    }
                  });
                };
                var setToken = function (token) {
                  db.auths.create({
                    client: req.session.client_id,
                    scopes: params.scope.split(' '),
                    user: req.session.user,
                    sub: req.session.sub || req.session.user,
                    code: token,
                    redirectUri: params.redirect_uri,
                    responseType: params.response_type,
                    status: 'created'
                  }, function (err, auth) {
                    if (!err && auth) {
                      setTimeout(function () {
                        db.auths.getByCode(token, function (err, auth) {
                          if (auth && auth.status == 'created') {
                            db.auths.destroy(auth, function (err) { console.log(err); });
                          }
                        });
                      }, 1000 * 60 * 10); //10 minutes
                      def.resolve({code: token});
                    } else {
                      def.reject(err || 'Could not create auth');
                    }
                  });

                };
                createToken();
                break;
              case 'id_token':
                var d = Math.round(new Date().getTime() / 1000);
                //var id_token = {
                def.resolve({
                  id_token: {
                    iss: req.protocol + '://' + req.headers.host,
                    sub: req.session.sub || req.session.user,
                    aud: params.client_id,
                    exp: d + 3600,
                    iat: d,
                    nonce: params.nonce
                  }
                });
                //def.resolve({id_token: jwt.encode(id_token, req.session.client_secret)});
                break;
              case 'token':
                var createToken = function () {
                  var token = crypto.createHash('md5').update(params.client_id).update(Math.random() + '').digest('hex');
                  db.accesses.getByToken(token, function (err, access) {
                    if (!access) {
                      setToken(token);
                    } else {
                      createToken();
                    }
                  });
                };
                var setToken = function (token) {
                  var obj = {
                    token: token,
                    type: 'Bearer',
                    expiresIn: 3600,
                    user: req.session.user,
                    client: req.session.client_id,
                    scopes: params.scope.split(' ')
                  };
                  db.accesses.create(obj, function (err, access) {
                    if (!err && access) {
                      setTimeout(function () {
                        access.destroy();
                      }, 1000 * 3600); //1 hour

                      def.resolve({
                        access_token: obj.token,
                        token_type: obj.type,
                        expires_in: obj.expiresIn
                      });
                    }
                  });
                };
                createToken();
                break;
            }
          });

          Q.allSettled(promises).then(function (results) {
            var resp = {};
            for (var i in results) {
              resp = extend(resp, results[i].value || {});
            }
            if (resp.access_token && resp.id_token) {
              var hbuf = crypto.createHmac('sha256', req.session.client_secret).update(resp.access_token).digest();
              resp.id_token.ht_hash = base64url(hbuf.toString('ascii', 0, hbuf.length / 2));
              resp.id_token = jwt.encode(resp.id_token, req.session.client_secret);
            }
            deferred.resolve({params: params, type: params.response_type != 'code' ? 'f' : 'q', resp: resp});
          });

          return deferred.promise;
        }
      })
        .then(function (obj) {
          var params = obj.params;
          var resp = obj.resp;
          var uri = url.parse(params.redirect_uri, true);
          if (params.state) {
            resp.state = params.state;
          }
          if (params.redirect_uri) {
            if (obj.type == 'f') {
              uri.hash = querystring.stringify(resp);
            } else {
              uri.query = resp;
            }
            res.redirect(url.format(uri));
          }
        })
        .fail(function (error) {
          if (error.type == 'error') {
            self.errorHandle(res, error.uri, error.error, error.msg);
          } else {
            res.redirect(error.uri);
          }
        });
    }
  ];
};

/**
 * consent
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.post('/consent', oidc.consent());
 *
 * This method saves the consent of the resource owner to a client request, or returns an access_denied error.
 *
 */
OpenIDConnect.prototype.consent = function () {
  var self = this;
  return [
    function (req, res, next) {
      var accept = req.param('accept');
      var return_url = req.param('return_url');
      //var client_id = req.query.client_id || req.body.client_id || false;
      if (accept) {
        var scopes = [];
        for (var i in req.session.scopes) {
          scopes.push(i);
        }
        db.consents.destroy({user: req.session.user, client: req.session.client_id}, function (err, result) {
          db.consents.create({
            user: req.session.user,
            client: req.session.client_id,
            scopes: scopes
          }, function (err, consent) {
            res.redirect(return_url);
          });
        });
      } else {
        var returl = url.parse(return_url, true);
        var redirect_uri = returl.query.redirect_uri;
        self.errorHandle(res, redirect_uri, 'access_denied', 'Resource Owner denied Access.');
      }
    }];
};


/**
 * token
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/token', oidc.token());
 *
 * This is the token endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.2
 *
 */
OpenIDConnect.prototype.token = function () {
  var self = this;
  var spec = {
    grant_type: true,
    code: false,
    redirect_uri: false,
    refresh_token: false,
    scope: false
  };

  return [
    function (req, res, next) {
      self.endpointParams(spec, req, res, next)
    },

    function (req, res, next) {
      var params = req.parsedParams;

      var client_key = req.body.client_id;
      var client_secret = req.body.client_secret;

      if (!client_key || !client_secret) {
        var authorization = parse_authorization(req.headers.authorization);
        if (authorization) {
          client_key = authorization[0];
          client_secret = authorization[1];
        }
      }
      if (!client_key || !client_secret) {
        self.errorHandle(res, params.redirect_uri, 'invalid_client', 'No client credentials found.');
      } else {

        Q.fcall(function () {
          //Step 2: check if client and secret are valid
          var deferred = Q.defer();
          db.clients.getByKeyAndSecret(client_key, client_secret, function (err, client) {
            if (err || !client) {
              deferred.reject({
                type: 'error',
                error: 'invalid_client',
                msg: 'Client doesn\'t exist or invalid secret.'
              });
            } else {
              deferred.resolve(client);
            }
          });
          return deferred.promise;
        })
          .then(function (client) {

            var deferred = Q.defer();

            switch (params.grant_type) {
              //Client is trying to exchange an authorization code for an access token
              case "authorization_code":
                //Step 3: check if code is valid and not used previously
                db.auths.getByCode(params.code, function (err, auth) {
                    if (!err && auth) {
                      if (auth.status != 'created') {
                        if (auth.refresh) {
                          auth.refresh.forEach(function (refresh) {
                            db.refreshes.destroy(refresh, function (err) { console.log(err); });
                          });
                        }
                        if (auth.access) {
                          auth.access.forEach(function (access) {
                            db.accesses.destroy(access, function (err) { console.log(err); });
                          });
                        }
                        db.auths.destroy(auth, function (err) { console.log(err); });
                        deferred.reject({
                          type: 'error',
                          error: 'invalid_grant',
                          msg: 'Authorization code already used.'
                        });
                      } else {
                        //obj.auth = a;
                        deferred.resolve({
                          auth: auth,
                          scopes: auth.scopes,
                          client: client,
                          user: auth.user,
                          sub: auth.sub
                        });
                      }
                    } else {
                      deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Authorization code is invalid.'});
                    }
                  });

                //Extra checks, required if grant_type is 'authorization_code'
                return deferred.promise.then(function (obj) {
                  //Step 4: check if grant_type is valid

                  if (obj.auth.responseType != 'code') {
                    throw {type: 'error', error: 'unauthorized_client', msg: 'Client cannot use this grant type.'};
                  }

                  //Step 5: check if redirect_uri is valid
                  if ((obj.auth.redirectUri || params.redirect_uri) && obj.auth.redirectUri != params.redirect_uri) {
                    throw {type: 'error', error: 'invalid_grant', msg: 'Redirection URI does not match.'};
                  }

                  return obj;
                });

                break;

              //Client is trying to exchange a refresh token for an access token
              case "refresh_token":

                //Step 3: check if refresh token is valid and not used previously
                db.refreshes.getByToken(params.refresh_token, function (err, refresh) {
                  if (!err && refresh) {
                    db.auths.getById(refresh.auth, function (err, auth) {
                        if (refresh.status != 'created') {
                          auth.access.forEach(function (access) {
                            db.accesses.destroy(access, function (err) { console.log(err); });
                          });
                          auth.refresh.forEach(function (refresh) {
                            db.refreshes.destroy(refresh, function (err) { console.log(err); });
                          });
                          db.auths.destroy(auth, function (err) { console.log(err); });
                          deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token already used.'});
                        } else {
                          refresh.status = 'used';
                          db.refreshes.update(refresh, function (err) { console.log(err); });
                          deferred.resolve({auth: auth, client: client, user: auth.user, sub: auth.sub});
                        }
                      });
                  } else {
                    deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token is not valid.'});
                  }
                });
                return deferred.promise.then(function (obj) {
                  if (params.scope) {
                    var scopes = params.scope.split(' ');
                    if (scopes.length) {
                      scopes.forEach(function (scope) {
                        if (obj.auth.scope.indexOf(scope) == -1) {
                          throw {
                            type: 'error',
                            uri: params.redirect_uri,
                            error: 'invalid_scope',
                            msg: 'Scope ' + scope + ' was not granted for this token.'
                          };
                        }
                      });
                      obj.scope = scopes;
                    }
                  } else {
                    obj.scope = obj.auth.scope;
                  }

                  return obj;
                });
                break;
              case 'client_credentials':
                if (!client.credentialsFlow) {
                  deferred.reject({
                    type: 'error',
                    error: 'unauthorized_client',
                    msg: 'Client cannot use this grant type.'
                  });
                } else {
                  deferred.resolve({scope: params.scope, auth: false, client: client});
                }
                return deferred.promise;
                break;
            }

          })
          .then(function (obj) {
            //Check if code was issued for client
            if (params.grant_type != 'client_credentials' && obj.client.key != client_key) {
              throw {type: 'error', error: 'invalid_grant', msg: 'The code was not issued for this client.'};
            }

            return obj;

          })
          .then(function (prev) {
            //Create access token
            /*var scopes = obj.scope;
             var auth = obj.auth;*/

            var createToken = function (model, cb) {
              var token = crypto.createHash('md5').update(Math.random() + '').digest('hex');
              model.getByToken(token, function (err, response) {
                if (!response) {
                  cb(token);
                } else {
                  createToken(model, cb);
                }
              });
            };
            var setToken = function (access, refresh) {
              db.refreshes.create({
                  token: refresh,
                  scopes: prev.scopes,
                  status: 'created',
                  auth: prev.auth ? prev.auth.id : null
                },
                function (err, refresh) {
                  setTimeout(function () {
                    db.refreshes.destroy(refresh, function (err) { console.log(err); });
                    if (refresh.auth) {
                      db.auths.getById(refresh.auth, function (err, auth) {
                          if (!auth.access.length && !auth.refresh.length) {
                            db.auths.destroy(auth, function (err) { console.log(err); });
                          }
                        });
                    }
                  }, 1000 * 3600 * 5); //5 hours

                  var d = Math.round(new Date().getTime() / 1000);
                  var id_token = {
                    iss: req.protocol + '://' + req.headers.host,
                    sub: prev.sub || prev.user || null,
                    aud: prev.client.key,
                    exp: d + 3600,
                    iat: d
                  };
                  db.accesses.create({
                      token: access,
                      type: 'Bearer',
                      expiresIn: 3600,
                      user: prev.user || null,
                      client: prev.client.id,
                      idToken: jwt.encode(id_token, prev.client.secret),
                      scopes: prev.scopes,
                      auth: prev.auth ? prev.auth.id : null
                    },
                    function (err, access) {
                      if (!err && access) {
                        if (prev.auth) {
                          prev.auth.status = 'used';
                          db.auths.update(prev.auth, function (err) { console.log(err); });
                        }

                        setTimeout(function () {
                          db.accesses.destroy(access, function (err) { console.log(err); });
                          if (access.auth) {
                            db.auths.getById(refresh.auth, function (err, auth) {
                                if (!auth.access.length && !auth.refresh.length) {
                                  db.auths.destroy(auth, function (err) { console.log(err); });
                                }
                              });
                          }
                        }, 1000 * 3600); //1 hour

                        res.json({
                          access_token: access.token,
                          token_type: access.type,
                          expires_in: access.expiresIn,
                          refresh_token: refresh.token,
                          id_token: access.idToken,
                          state: req.body.state
                        });
                      }
                    });
                });
            };
            createToken(db.accesses, function (access) {
              createToken(db.refreshes, function (refresh) {
                setToken(access, refresh);
              });
            });
          })
          .fail(function (error) {
            if (error.type == 'error') {
              self.errorHandle(res, params.redirect_uri, error.error, error.msg);
            } else {
              res.redirect(error.uri);
            }
          });
      }
    }];
};


/**
 * check
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/api/user', oidc.check('openid', /profile|email/), function(req, res, next) { ... });
 *
 * If no arguments are given, checks if access token is valid.
 *
 * The other arguments may be of type string or regexp.
 *
 * This function is used to check if user logged in, if an access_token is present, and if certain scopes where granted to it.
 */
OpenIDConnect.prototype.check = function () {
  //Seguir desde acá!!!!
  var scopes = Array.prototype.slice.call(arguments, 0);
  if (!util.isArray(scopes)) {
    scopes = [scopes];
  }
  var self = this;
  spec = {
    access_token: false
  };

  return [
    function (req, res, next) {
      self.endpointParams(spec, req, res, next);
    },
    function (req, res, next) {
      var params = req.parsedParams;
      if (!scopes.length) {
        next();
      } else {
        if (!params.access_token) {
          params.access_token = (req.headers['authorization'] || '').indexOf('Bearer ') === 0 ? req.headers['authorization'].replace('Bearer', '').trim() : false;
        }
        if (params.access_token) {
          db.accesses.getByToken(params.access_token, function (err, access) {
              if (!err && access) {
                var errors = [];

                scopes.forEach(function (scope) {
                  if (typeof scope == 'string') {
                    if (access.scopes.indexOf(scope) == -1) {
                      errors.push(scope);
                    }
                  } else if (util.isRegExp(scope)) {
                    var inS = false;
                    access.scopes.forEach(function (s) {
                      if (scope.test(s)) {
                        inS = true;
                      }
                    });
                    !inS && errors.push('(' + scope.toString().replace(/\//g, '') + ')');
                  }
                });
                if (errors.length > 1) {
                  var last = errors.pop();
                  self.errorHandle(res, null, 'invalid_scope', 'Required scopes ' + errors.join(', ') + ' and ' + last + ' where not granted.');
                } else if (errors.length > 0) {
                  self.errorHandle(res, null, 'invalid_scope', 'Required scope ' + errors.pop() + ' not granted.');
                } else {
                  req.check = req.check || {};
                  req.check.scopes = access.scopes;
                  next();
                }
              } else {
                self.errorHandle(res, null, 'unauthorized_client', 'Access token is not valid.');
              }
            });
        } else {
          self.errorHandle(res, null, 'unauthorized_client', 'No access token found.');
        }
      }
    }
  ];
};

/**
 * userInfo
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/api/user', oidc.userInfo());
 *
 * This function returns the user info in a json object. Checks for scope and login are included.
 */
OpenIDConnect.prototype.userInfoByAccessToken = function () {
  return [
    function (req, res, next) {
      if (!req.params.access_token) {
        req.params.access_token = (req.headers['authorization'] || '').indexOf('Bearer ') === 0 ? req.headers['authorization'].replace('Bearer', '').trim() : false;
      }
      if (req.params.access_token) {
        db.accesses.getByToken(req.params.access_token, function (err, access) {
          req.session.user = access.user;
          next();
        });
      } else {
        res.send(400, 'No AccessToken!');
      }
    }
  ].concat(this.userInfo());
};

OpenIDConnect.prototype.userInfo = function () {
  var self = this;
  return [
    self.check('openid', /profile|email/),
    function (req, res, next) {
      db.users.getById(req.session.user, function (err, user) {
        if (req.check.scopes.indexOf('profile') != -1) {
          user.sub = req.session.sub || req.session.user;
          delete user.password;
          res.json(user);
        } else {
          res.json({email: user.email});
        }
      });
    }
  ];
};

/**
 * removetokens
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/logout', oidc.removetokens(), function(req, res, next) { ... });
 *
 * this function removes all tokens that were issued to the user
 * access_token is required either as a parameter or as a Bearer token
 */
OpenIDConnect.prototype.removetokens = function () {
  var self = this,
    spec = {
      access_token: false //parameter not mandatory
    };

  return [
    function (req, res, next) {
      self.endpointParams(spec, req, res, next);
    },
    function (req, res, next) {
      var params = req.parsedParams;

      if (!params.access_token) {
        params.access_token = (req.headers['authorization'] || '').indexOf('Bearer ') === 0 ? req.headers['authorization'].replace('Bearer', '').trim() : false;
      }
      if (params.access_token) {
        //Delete the provided access token, and other tokens issued to the user
        db.accesses.getByToken(params.access_token, function (err, access) {
            if (!err && access) {
              db.auths.getByUser(access.user, function (err, auth) {
                  if (!err && auth) {
                    auth.accessTokens.forEach(function (access) {
                      db.accesses.destroy(access, function (err) { console.log(err); });
                    });
                    auth.refreshTokens.forEach(function (refresh) {
                      db.refreshes.destroy(refresh, function (err) { console.log(err); });
                    });
                    db.auths.destroy(auth, function (err) { console.log(err); });
                  }
                  db.accesses.getByUser(access.user, function (err, accesses) {
                      if (!err && accesses) {
                        accesses.forEach(function (access) {
                          db.accesses.destroy(access, function (err) { console.log(err); });
                        });
                      }
                      return next();
                    });
                });
            } else {
              self.errorHandle(res, null, 'unauthorized_client', 'Access token is not valid.');
            }
          });
      } else {
        self.errorHandle(res, null, 'unauthorized_client', 'No access token found.');
      }
    }
  ];
};

module.exports.oidc = function (options) {
  return new OpenIDConnect(options);
};

module.exports.defaults = function () {
  return defaults;
};
