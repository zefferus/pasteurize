'use strict';

/* eslint func-names: 0, max-len: 0, no-unused-vars: 0 */

import test from 'ava';

import { Pasteurize } from '../src/pasteurize.js';

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

test('Errors if keylength bad', (t) => {
  t.plan(2);

  t.throws(() => { var pasteurize = new Pasteurize(null, 256, 100, 'sha512'); }, TypeError);
  t.throws(() => { var pasteurize = new Pasteurize(-1, 256, 100, 'sha512'); }, TypeError);
});

test('Errors if saltLength bad', (t) => {
  t.plan(2);

  t.throws(() => { var pasteurize = new Pasteurize(64, null, 100, 'sha512'); }, TypeError);
  t.throws(() => { var pasteurize = new Pasteurize(64, -1, 100, 'sha512'); }, TypeError);
});

test('Errors if iterations bad', (t) => {
  t.plan(2);

  t.throws(() => { var pasteurize = new Pasteurize(64, 256, null, 'sha512'); }, TypeError);
  t.throws(() => { var pasteurize = new Pasteurize(64, 256, -1, 'sha512'); }, TypeError);
});

test('Errors if digest bad', (t) => {
  t.plan(2);

  t.throws(() => { var pasteurize = new Pasteurize(64, 256, 100, null); }, TypeError);
  t.throws(() => { var pasteurize = new Pasteurize(64, 256, 100, 'obviously bad digest'); }, TypeError);
});

test.cb('Async verify good password', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.password1, (err: Error, verified: boolean) => {
    t.ifError(err);
    t.truthy(verified);
    t.end();
  });
});

test('Async verify returns promise', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  return pasteurize.verifyPassword('password1', internals.hashes.password1)
  .then((verified) => {
    t.truthy(verified);
  });
});

test.cb('Async verify bad password', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.password2, (err: Error, verified: boolean) => {
    t.ifError(err);
    t.falsy(verified);
    t.end();
  });
});

test('Sync verify good password', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password2', internals.hashes.password2);
  t.truthy(verified);
});

test('Sync verify bad password', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password2', internals.hashes.corrupted.password2);
  t.falsy(verified);
});

test.cb('Async hash password', (t) => {
  t.plan(4);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.hashPassword('password1', (err: Error, hash: string) => {
    t.ifError(err);
    t.truthy(hash);

    pasteurize.verifyPassword('password1', hash, (err: Error, verified: boolean) => {
      t.ifError(err);
      t.truthy(verified);
      t.end();
    });
  });
});

test('Async hash password returns promise', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  return pasteurize.hashPassword('password1')
  .then((hash) => pasteurize.verifyPassword('password1', hash))
  .then((verified) => {
    t.truthy(verified);
  });
});

test('Sync hash password', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var hash = pasteurize.hashPasswordSync('password1');
  t.truthy(hash);

  var verified = pasteurize.verifyPasswordSync('password1', hash);
  t.truthy(verified);
});

test.cb('Bad hash in async verification', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', 'abc', (err: Error, verified: boolean) => {
    t.ifError(err);
    t.falsy(verified);
    t.end();
  });
});

test('Bad hash in sync verification', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  var verified = pasteurize.verifyPasswordSync('password1', 'abc');
  t.falsy(verified);
});

test.cb('Corrupted hash in async verification', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password1', internals.hashes.corrupted.password1,
    (err: Error, verified: boolean) => {
      t.truthy(err);
      t.falsy(verified);
      t.end();
    });
});

test('Corrupted hash in sync verification', (t) => {
  t.plan(1);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  t.throws(() => pasteurize.verifyPasswordSync('password1', internals.hashes.corrupted.password1));
});

test.cb('Hash with bad digest in verification', (t) => {
  t.plan(2);
  var pasteurize = new Pasteurize(64, 256, 100, 'sha512');

  pasteurize.verifyPassword('password2', internals.hashes.corrupted.baddigest,
    (err: Error, verified: boolean) => {
      t.truthy(err);
      t.falsy(verified);
      t.end();
    });
});
