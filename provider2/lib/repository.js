'use strict';

var viewmodel = require('viewmodel');

var repo;

module.exports = {
  init: function (options, callback) {
    viewmodel.write(options, function (err, repository) {
      if (err) {
        console.log(err);
        callback(err);
        return;
      }

      repository.on('disconnect', function () {
        console.log('Killing myself, since I got a disconnect from the repository...');
        /*eslint no-process-exit:0*/
        process.exit(1);
      });

      console.log('successfully initialized viewmodel');

      repo = repository;
      callback(err, repo);
    });
  },

  repository: function () {
    return repo;
  }
};