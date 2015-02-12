'use strict';

var path = require('path'),
  async = require('async'),
  repository = require('../repository').repository(),
  repo = repository.extend({
    collectionName: path.basename(__filename, '.js'),
    indexes: ['user', 'client']
  });

//user
//client
//scopes

module.exports = {

  findByUser: function(userId, callback) {
    repo.find({ user: userId }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      callback(null, vms.toJSON());
    });
  },

  getByUserAndClient: function(userId, clientId, callback) {
    repo.find({ user: userId, client: clientId }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, vms[0].toJSON());
      }
      callback(null, null);
    });
  },

  destroy: function(data, callback) {
    if (data.id) {
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
    } else {
      if (!data.user) {
        return callback(new Error('Please pass in a user id!'));
      }

      if (!data.client) {
        return callback(new Error('Please pass in a client id!'));
      }

      repo.find({ user: data.user, client: data.client }, function (err, vms) {
        if (err) {
          return callback(err);
        }
        async.each(vms, function (vm, callback) {
          vm.destroy();
          repo.commit(vm, callback);
        }, function (err) {
          if (err) {
            return callback(err);
          }
          callback(err, data);
        });
      });
    }
  },

  create: function (data, callback) {
    if (!data.user) {
      return callback(new Error('Please pass in a user id!'));
    }

    if (!data.client) {
      return callback(new Error('Please pass in a client id!'));
    }

    data.scopes = data.scopes || [];

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

  update: function (data, callback) {
    if (!data.user) {
      return callback(new Error('Please pass in a user id!'));
    }

    if (!data.client) {
      return callback(new Error('Please pass in a client id!'));
    }

    data.scopes = data.scopes || [];

    this.getByUserAndClient(data.user, data.client, function (err, consent) {
      if (err) {
        return callback(err);
      }

      if (!consent) {
        return callback(new Error('Not an existing consent!'));
      }

      repo.get(consent.id, function (err, vm) {
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

    });
  }

};
