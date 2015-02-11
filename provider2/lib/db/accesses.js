'use strict';

var path = require('path'),
  repository = require('../repository').repository(),
  repo = repository.extend({
    collectionName: path.basename(__filename, '.js'),
    indexes: ['token', 'user']
  });

//token
//type
//idToken
//expiresIn
//scopes
//client
//user
//auth

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

  getByToken: function(token, callback) {
    repo.find({ token: token }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, vms[0].toJSON());
      }
      callback(null, null);
    });
  },

  findByUser: function(user, callback) {
    repo.find({ user: user }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      callback(null, vms.toJSON());
    });
  },

  create: function (data, callback) {
    if (!data.token) {
      return callback(new Error('Please pass in a token!'));
    }

    if (!data.type) {
      return callback(new Error('Please pass in a type!'));
    }

    if (!data.scopes || data.scopes.length === 0) {
      return callback(new Error('Please pass in scopes!'));
    }

    if (!data.client) {
      return callback(new Error('Please pass in a client id!'));
    }

    if (!data.user) {
      return callback(new Error('Please pass in a user id!'));
    }

    data.expiresIn = data.expiresIn || 0;

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
  }

};
