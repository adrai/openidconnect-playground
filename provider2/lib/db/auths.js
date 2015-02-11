'use strict';

var path = require('path'),
  repository = require('../repository').repository(),
  repo = repository.extend({
    collectionName: path.basename(__filename, '.js'),
    indexes: ['code', 'user']
  });

//client
//scopes
//user
//sub
//code
//redirectUri
//responseType
//status
//accessTokens
//refreshTokens

module.exports = {

  getById: function(id, callback) {
    repo.get(id, function (err, vm) {
      if (err) {
        return callback(err);
      }
      if (vm.actionOnCommit === 'create') {
        return callback(null, null);
      }
      callback(null, vm.toJSON());
    });
  },

  getByCode: function(code, callback) {
    repo.find({ code: code }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, vms[0].toJSON());
      }
      callback(null, null);
    });
  },

  getByUser: function(user, callback) {
    repo.find({ user: user }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, vms[0].toJSON());
      }
      callback(null, null);
    });
  },

  create: function (data, callback) {
    if (!data.user) {
      return callback(new Error('Please pass in a user id!'));
    }

    if (!data.sub) {
      return callback(new Error('Please pass in a sub!'));
    }

    if (!data.client) {
      return callback(new Error('Please pass in a client id!'));
    }

    if (!data.scopes || data.scopes.length === 0) {
      return callback(new Error('Please pass in scopes!'));
    }

    if (!data.code) {
      return callback(new Error('Please pass in a code!'));
    }

    if (!data.redirectUri) {
      return callback(new Error('Please pass in a redirectUri!'));
    }

    if (!data.responseType) {
      return callback(new Error('Please pass in a responseType!'));
    }

    if (!data.status) {
      return callback(new Error('Please pass in a status!'));
    }

    data.accessTokens = data.accessTokens || [];
    data.refreshTokens = data.refreshTokens || [];

    repo.get(function (err, vm) {
      if (err) {
        return callback(err);
      }

      vm.set(data);

      repo.commit(vm, function (err, vm) {
        if (err) {
          return callback(err);
        }
        callback(null, vm.toJSON());
      })
    });
  },

  destroy: function(data, callback) {
    if (!data.id) {
      return callback(new Error('Please pass in an id!'));
    }

    repo.get(data.id, function (err, vm) {
      if (err) {
        return callback(err);
      }

      vm.destroy();

      repo.commit(vm, function (err, vm) {
        if (err) {
          return callback(err);
        }
        callback(null, vm.toJSON());
      })
    });
  }

};
