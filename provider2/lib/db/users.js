'use strict';

var path = require('path'),
  hashPassword = require('../hashPassword'),
  repository = require('../repository').repository(),
  repo = repository.extend({
    collectionName: path.basename(__filename, '.js'),
    indexes: ['email']
  });

//name
//given_name
//middle_name
//family_name
//profile
//email
//password
//picture
//birthdate
//gender
//phone_number

function cleanUser (user) {
  delete user.password;
  delete user.salt;
  return user;
}

module.exports = {

  getById: function(id, callback) {
    repo.get(id, function (err, vm) {
      if (err) {
        return callback(err);
      }
      if (vm.actionOnCommit === 'create') {
        return callback(null, null);
      }
      callback(null, cleanUser(vm.toJSON()));
    });
  },

  getOneByEmail: function(email, callback) {
    repo.find({ email: email }, function (err, vms) {
      if (err) {
        return callback(err);
      }
      if (vms.length > 0) {
        return callback(null, cleanUser(vms[0].toJSON()));
      }
      callback(null, null);
    });
  },

  create: function (data, callback) {
    if (!data.given_name || !data.family_name) {
      return callback(new Error('Please define a given_name and a family_name!'));
    }

    if (!data.password || !data.passConfirm) {
      return callback(new Error('Please define a password!'));
    }

    if (data.password !== data.passConfirm) {
      return callback(new Error('Password not matching with password confirmation!'));
    }

    if (!data.name) {
      data.name = data.given_name + ' ' + (data.middle_name ? data.middle_name + ' ' : '') + data.family_name;
    }

    hashPassword(data.password, function (err, hash, salt) {
      if (err) {
        return callback(err);
      }

      delete data.passConfirm;

      repo.get(function (err, vm) {
        if (err) {
          return callback(err);
        }

        vm.set(data);
        vm.set('password', hash);
        vm.set('salt', salt);

        repo.commit(vm, function (err, vm) {
          if (err) {
            return callback(err);
          }
          callback(null, cleanUser(vm.toJSON()));
        });
      });
    });
  },

  update: function (data, callback) {
    if (!data.id) {
      return callback(new Error('Please pass in an id!'));
    }

    if (data.password && !data.passConfirm) {
      return callback(new Error('Please confirm the password!'));
    }

    if (data.password && (data.password !== data.passConfirm)) {
      return callback(new Error('Password not matching with password confirmation!'));
    }

    if (!data.name) {
      data.name = data.given_name + ' ' + (data.middle_name ? data.middle_name + ' ' : '') + data.family_name;
    }

    if (!data.password) {
      repo.get(data.id, function (err, vm) {
        if (err) {
          return callback(err);
        }

        delete data.salt;
        delete data.password;
        delete data.passConfirm;
        vm.set(data);

        repo.commit(vm, function (err, vm) {
          if (err) {
            return callback(err);
          }
          callback(null, cleanUser(vm.toJSON()));
        });
      });
    } else {
      hashPassword(data.password, function (err, hash, salt) {
        if (err) {
          return callback(err);
        }

        delete data.passConfirm;

        repo.get(function (err, vm) {
          if (err) {
            return callback(err);
          }

          vm.set(data);
          vm.set('password', hash);
          vm.set('salt', salt);

          repo.commit(vm, function (err, vm) {
            if (err) {
              return callback(err);
            }
            callback(null, cleanUser(vm.toJSON()));
          });
        });
      });
    }
  }

};
