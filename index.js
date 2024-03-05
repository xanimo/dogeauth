'use strict';

var dogeauth;
if (process.browser) {
  dogeauth = require('./lib/dogeauth-browserify');
} else {
  dogeauth = require('./lib/dogeauth-node');

  // add node-specific encrypt/decrypt
  dogeauth.encrypt = require('./lib/encrypt');
  dogeauth.decrypt = require('./lib/decrypt');
  dogeauth.middleware = require('./lib/middleware/dogeauth');
}

module.exports = dogeauth;
