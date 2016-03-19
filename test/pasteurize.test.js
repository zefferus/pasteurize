'use strict';

/* eslint func-names: 0, max-len: 0, no-unused-vars: 0 */

var tap = require('tap');
var test = tap.test;

var Pasteurize = require('../src/pasteurize.js');

var internals = {
  hashes: {
    password1: '$pbkdf2-sha512$100000$.V.rNSZk7F0L4dwbQyhl7H3vnXPuXUuJ8f6fcy4lJCQE4FwLgVAKgTAm5FzrnVNqTSml1DqH8H5vzXkvJYQw5tzbmzNmTOl9b.2d0xrDGIOQcg7BmJNS6p2z1npPifEew7h3LsWY05rznpPy3htjTOmdc24NYax1TokxBuA8x5gTAiCE0Np7z7l3jtF6L.Vc630PoTSmdC5FaA2B8F7LWUtprTUGwHivFUIo5TyHsBaCcC6FkPIeg3COUer9n3NuTSnlvDem1JpTai0FYGzNOQdgDCHE.P/fW6tVCmGsVeq9l1LKmZNSSmntHUNIidH6X2uNcc7Z29sbQ0jJuXdOCQ$1ilkE2RD6OmiRrD7KCWvqpz5.Z4t60Zs2e1c/M6e86S5LxP.8y1uEI6u5VimtFNPfnvnfECAi7QMVJDQDXGXxw',
    password2: '$pbkdf2-sha512$100000$dU5JKQXgHIPQWislBACgdC6FMAZA6N0bQ4gxJsSYs3aulZIyhpASwlgLAQAgxDhn7D3nXAth7B2j1JpTihGCUEqp9Z4zBkDo3ftf673XujcGoBSiVIoxRihFyFlLidHa21sLwRgD4Nzbm/M.BwDgnDNG6N3bOyeEMEbIec95r/WekxLifI8xZsx5D6EUQqj13vs/hzDmPIcQYozx/p9T6h2DUAphbK01BoAQIiTEuDdGKAXgXGtNScmZE6I0xvhfy/k/J6S0do6R8h5jzNn7f.99rxXCeM.ZszZmTCmlNOZ8r/X.n1PKmVNKiXFOidE6x9i7V0qJkRKCsBaCUKp1rg$fyX4fKfOrvNoiG48O3mATt7Hit7VVY8uW0UvUMEZSKCIWV3Ur5aGIh62q8WAmQQBp/ugHdI9UjaS.MNRc/ymqQ',
    corrupted: {
      password1: '$pbkdf2-sha512$100000$.V.rNSZk7F0L4dwbQyhl7H3vnXPuXUuJ8f6fcy4lJCQE4FwLgVAKgTAm5FzrnVNqTSml1DqH8H5vzXkvJYQw5tzbmzNmTOl9b.2d0xrDGIOQcg7BmJNS6p2z1npPifEew7h3LsWY05rznpPy3htjTOmdc24NYax1TokxBuA8x5gTAiCE0Np7z7l3jtF6L.Vc630PoTSmdC5FaA2B8F7LWUtprTUGwHivFUIo5TyHsBaCcC6FkPIeg3COUer9n3NuTSnlvDem1JpTai0FYGzNOQdgDCHE.P/fW6tVCmGsVeq9l1LKmZNSSmntHUNIidH6X2uNcc7Z29sbQ0jJuXdO$1ilkE2RD6OmiRrD7KCWvqpz5.Z4t60Zs2e1c/M6e86S5LxP.8y1uEI6u5VimtFNPfnvnfECAi7QMVJDQDXGXx',
      password2: '$pbkdf2-sha512$100000$dU5JKQXgHIPQWislBACgdC6FMAZA6N0bQ4gxJsSYs3aulZIyhpASwlgLAQAgxDhn7D3nXAth7B2j1JpTihGCUEqp9Z4zBkDo3ftf673XujcGoBSiVIoxRihFyFlLidHa21sLwRgD4Nzbm/M.BwDgnDNG6N3bOyeEMEbIec95r/WekxLifI8xZsx5D6EUQqj13vs/hzDmPIcQYozx/p9T6h2DUAphbK01BoAQIiTEuDdGKAXgXGtNScmZE6I0xvhfy/k/J6S0do6R8h5jzNn7f.99rxXCeM.ZszZmTCmlNOZ8r/X.n1PKmVNKiXFOidE6x9i7V0qJkRKCsBaCUKp$fyX4fKfOrvNoiG48O3mATt7Hit7VVY8uW0UvUMEZSKCIWV3Ur5aGIh62q8WAmQQBp/ugHdI9UjaS.MNRc/y',
      baddigest: '$pbkdf2-shaxxx$100000$dU5JKQXgHIPQWislBACgdC6FMAZA6N0bQ4gxJsSYs3aulZIyhpASwlgLAQAgxDhn7D3nXAth7B2j1JpTihGCUEqp9Z4zBkDo3ftf673XujcGoBSiVIoxRihFyFlLidHa21sLwRgD4Nzbm/M.BwDgnDNG6N3bOyeEMEbIec95r/WekxLifI8xZsx5D6EUQqj13vs/hzDmPIcQYozx/p9T6h2DUAphbK01BoAQIiTEuDdGKAXgXGtNScmZE6I0xvhfy/k/J6S0do6R8h5jzNn7f.99rxXCeM.ZszZmTCmlNOZ8r/X.n1PKmVNKiXFOidE6x9i7V0qJkRKCsBaCUKp1rg$fyX4fKfOrvNoiG48O3mATt7Hit7VVY8uW0UvUMEZSKCIWV3Ur5aGIh62q8WAmQQBp/ugHdI9UjaS.MNRc/ymqQ'
    }
  }
};

test('Errors if not instantiated new', function (t) {
  t.plan(1);

  t.throws(function () {
    var pasteurize = Pasteurize(64, 256, 100, 'sha512');
  });
  t.end();
});

test('Errors if keyLength bad', function(t) {
  t.plan(4);

  t.throws(function () {
    var pasteurize = new Pasteurize();
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(-1);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(null);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize('x');
  }, TypeError);

  t.end();
});

test('Errors if saltLength bad', function(t) {
  t.plan(4);

  t.throws(function () {
    var pasteurize = new Pasteurize(64);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, -1);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, null);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 'x');
  }, TypeError);

  t.end();
});

test('Errors if iterations bad', function(t) {
  t.plan(4);

  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, -1);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, null);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, 'x');
  }, TypeError);

  t.end();
});

test('Errors if digest bad', function(t) {
  t.plan(4);

  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, 100);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, 100, 512);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, 100, null);
  }, TypeError);
  t.throws(function () {
    var pasteurize = new Pasteurize(64, 256, 100, 'obviously bad digest');
  }, TypeError);

  t.end();
});

test('Async verify good password', function (t) {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.password1, function (err, verified) {
    t.ifError(err);
    t.ok(verified);
    t.end();
  });
});

test('Async verify bad password', function (t)  {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.password2, function (err, verified) {
    t.ifError(err);
    t.notOk(verified);
    t.end();
  });
});

test('Sync verify good password', function (t)  {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password2', internals.hashes.password2);
  t.ok(verified);
});

test('Sync verify bad password', function (t)  {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password2', internals.hashes.corrupted.password2);
  t.notOk(verified);
});

test('Async hash password', function (t)  {
  t.plan(4);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.hashPassword('password1', function (err, hash) {
    t.ifError(err);
    t.ok(hash);

    pasteurize.verifyPassword('password1', hash, function (err, verified) {
      t.ifError(err);
      t.ok(verified);
      t.end();
    });
  });
});

test('Sync hash password', function (t)  {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var hash = pasteurize.hashPasswordSync('password1');
  t.ok(hash);

  var verified = pasteurize.verifyPasswordSync('password1', hash);
  t.ok(verified);
  t.end();
});

test('Bad hash in async verification', function (t)  {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', 'abc', function (err, verified) {
    t.ifError(err);
    t.notOk(verified);
    t.end();
  });
});

test('Bad hash in sync verification', function (t)  {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password1', 'abc');
  t.notOk(verified);
  t.end();
});

test('Corrupted hash in async verification', function (t)  {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.corrupted.password1,
    function (err, verified) {
      t.ok(err);
      t.notOk(verified);
      t.end();
    });
});

test('Corrupted hash in sync verification', function (t)  {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  t.throws(function () {
    return pasteurize.verifyPasswordSync('password1', internals.hashes.corrupted.password1);
  });
  t.end();
});

test('Hash with bad digest in verification', function (t)  {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password2', internals.hashes.corrupted.baddigest,
    function (err, verified) {
      t.ok(err);
      t.notOk(verified);
      t.end();
    });
});
