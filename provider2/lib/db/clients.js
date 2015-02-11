'use strict';

var path = require('path'),
  repository = require('../repository').repository(),
  uuid = require('node-uuid').v4,
  repo = repository.extend({
    collectionName: path.basename(__filename, '.js'),
    indexes: ['key', 'secret']
  });

//key
//secret
//name
//image
//redirect_uris
//isOwn


module.exports = {

  getById: function(id, callback) {
    repo.get(id, function (err, vm) {
      if (err) {
        return callback(err);
      }
      if (vm.actionOnCommit === 'create') {
        return callback(null, null);
      }
      vm.set('key', vm.id);
      callback(null, vm.toJSON());
    });
  },

  getByKey: function(key, secret, callback) {
    repo.find({ key: key }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, vms[0].toJSON());
      }
      callback(null, null);
    });
  },

  getByKeyAndSecret: function(key, secret, callback) {
    repo.find({ key: key, secret: secret }, function (err, vms) {
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
    if (!data.id && !data.key) {
      return callback(new Error('Please pass in an id or a key!'));
    }

    if (!data.secret) {
      data.secret = uuid().toString();
    }

    if (data.id && !data.key) {
      data.key = data.id;
    }

    if (!data.name) {
      return callback(new Error('Please define a name!'));
    }

    if (!data.redirect_uris || data.redirect_uris.length === 0) {
      return callback(new Error('Please define redirect_uris!'));
    }

    if (data.id) {
      repo.get(data.id, function (err, vm) {
        if (err) {
          return callback(err);
        }

        if (vm.actionOnCommit !== 'create') {
          return callback(new Error('Passed id already existing!'));
        }

        vm.set(data);

        repo.commit(vm, function (err, vm) {
          if (err) {
            return callback(err);
          }
          callback(null, vm.toJSON());
        });
      });
    } else {
      repo.find({ key: data.key }, function (err, vms) {
        if (err) {
          return callback(err);
        }

        if (vms.length > 0) {
          return callback(new Error('Client already existing!'));
        }

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
          });
        });
      });
    }
  }

};
