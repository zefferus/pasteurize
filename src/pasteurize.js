'use strict';

var Crypto = require('crypto');

var internals = {};

/**
 * Creates a new Pasteurize object.
 * @constructor

 * @param {number} keyLength - The desired length of the hashed output. Must be
 *     non-negative.
 * @param {number} saltLength - The number of bytes to use for the salt. Must be
 *     non-negative.
 * @param {number} iterations - The number of iterations to run the PBKDF2
 *     algorithm. Must be non-negative.
 * @param {string} digest - One of the HMAC digest algorithms supported by Node.js.
 *
 * @throws {Error|TypeError} If Pasteurize isn't instantiated using new or if
 *     any parameter isn't of the required type.
 */
exports = module.exports = internals.Pasteurize = Pasteurize;
function Pasteurize(keyLength, saltLength, iterations, digest) {
  if (!(this instanceof internals.Pasteurize)) {
    throw new Error('Pasteurize must be instantiated using new');
  }

  if (typeof keyLength !== 'number' || keyLength < 0) {
    throw new TypeError('Key Length must be a non-negative number');
  }
  if (typeof saltLength !== 'number' || saltLength < 0) {
    throw new TypeError('Salt Length must be a non-negative number');
  }
  if (typeof iterations !== 'number' || iterations < 0) {
    throw new TypeError('Iterations must be a non-negative number');
  }
  if (typeof digest !== 'string' || Crypto.getHashes().indexOf(digest) < 0) {
    throw new TypeError('Unsupported digest type');
  }

  this._config = {
    keyLength: keyLength,
    saltLength: saltLength,
    iterations: iterations,
    digest: digest
  };
}

// Private methods

// *****************************************************************************
// Note: The following private methods are to ensure compatibility with Python's
// passlib (https://bitbucket.org/ecollins/passlib/) and the way it generates
// hashes.
// *****************************************************************************

// Converts a Buffer to an adapted-base64 string
function ab64encode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '.').replace(/\=+$/, '');
}

// Converts an adapted-base64 string to a Buffer
function ab64decode(data) {

  // We have to look at the last set of 4 bytes
  var offset = data.length & 3;

  if (offset === 1) {
    // We should never end up with two bytes of offset after padding is removed
    throw new Error('invalid base64 input');
  }

  var padding = '';

  // Add back the appropriate amount of equals padding to finish the string
  switch (offset) {
    case 2:
      padding = '==';
      break;
    case 3:
      padding = '=';
      break;
  }

  return new Buffer(data.replace(/\./g, '+') + padding, 'base64');
}

// Creates a hash string compatible with passlib
function makeHashString(digest, iterations, salt, encoded) {
  return [
    '$pbkdf2-' + digest,
    iterations,
    ab64encode(salt),
    ab64encode(encoded)
  ].join('$');
}

// Parses the components of a passlib hash
function parseHashString(hash) {
  return hash.match(/^\$pbkdf2-(\w+)\$(\d+)\$([A-Za-z0-9\.\/]+)\$([A-Za-z0-9\.\/]+$)/);
}

// Extracts the components of a hash into usable form
function extractHashComponents(hash) {

  var match = parseHashString(hash);

  if (!match) {
    return null;
  }

  var digest = match[1];

  if (Crypto.getHashes().indexOf(digest) < 0) {
    throw new TypeError('Unsupported digest');
  }

  var iterations = parseInt(match[2], 10),
    salt = ab64decode(match[3]),
    checksum = match[4],
    checksum_b64 = ab64decode(checksum);

  return {
    digest: digest,
    iterations: iterations,
    salt: salt,
    checksum: checksum,
    checksum_b64: checksum_b64
  };
}


// Public methods

/**
 * Asynchronously hashes a password.
 *
 * @param  {string} password - The password to hash.
 * @param  {hashPassword~cb} cb - Callback
 */
internals.Pasteurize.prototype.hashPassword = hashPassword;
function hashPassword(password, cb) {

  var saltLength = this._config.saltLength;
  var iterations = this._config.iterations;
  var keyLength = this._config.keyLength;
  var digest = this._config.digest;

  Crypto.randomBytes(saltLength, function receiveBytes(err, salt) {

    // istanbul ignore if
    if (err) {
      return cb(err);
    }

    return Crypto.pbkdf2(password, salt, iterations, keyLength, digest,
      function makeHash(err, hash) {

        // istanbul ignore if
        if (err) {
          return cb(err);
        }

        return cb(null, makeHashString(digest, iterations, salt, hash));
      });
  });
}


/**
 * Synchronously hashes a password.
 *
 * @param  {string} password - The password to hash.
 * @return {string} The resulting password hash.
 */
internals.Pasteurize.prototype.hashPasswordSync = hashPasswordSync;
function hashPasswordSync(password) {

  var saltLength = this._config.saltLength;
  var iterations = this._config.iterations;
  var keyLength = this._config.keyLength;
  var digest = this._config.digest;

  var salt = Crypto.randomBytes(saltLength);
  var hash = Crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest);

  return makeHashString(digest, iterations, salt, hash);
}


/**
 * Asynchronously verifies whether a password matches the given hash.
 *
 * @param  {string} password - The password to verify.
 * @param  {string} hashedPassword - The hashed password to verify against.
 * @param  {verifyPassword~cb} cb - Callback
 */
internals.Pasteurize.prototype.verifyPassword = verifyPassword;
function verifyPassword(password, hashedPassword, cb) {

  try {

    var hashComponents = extractHashComponents(hashedPassword);

    if (!hashComponents) {
      process.nextTick(function nextTick() {
        cb(null, false);
      });
      return;
    }

    var digest = hashComponents.digest,
      iterations = hashComponents.iterations,
      salt = hashComponents.salt,
      checksum = hashComponents.checksum,
      checksum_b64 = hashComponents.checksum_b64;

    Crypto.pbkdf2(password, salt, iterations, checksum_b64.length, digest,
      function makeHash(err, checkHash) {

        // istanbul ignore if
        if (err) {
          return cb(err);
        }

        return cb(null, ab64encode(checkHash) === checksum);
      });

  } catch (e) {

    process.nextTick(function nextTick() {
      return cb(e);
    });
    return;
  }
}


/**
 * Synchronously verifies whether a password matches the given hash.
 *
 * @param  {string} password - The password to verify.
 * @param  {string} hashedPassword - The hashed password to verify.
 * @return {boolean} Whether the password and hash match.
 * @throws {Error} If the hash is corrupted and unreadable.
 */
internals.Pasteurize.prototype.verifyPasswordSync = verifyPasswordSync;
function verifyPasswordSync(password, hashedPassword) {

  var hashComponents = extractHashComponents(hashedPassword);

  if (!hashComponents) {
    return false;
  }

  var digest = hashComponents.digest,
    iterations = hashComponents.iterations,
    salt = hashComponents.salt,
    checksum = hashComponents.checksum,
    checksum_b64 = hashComponents.checksum_b64;

  // verify the salt and hash against the password
  var checkHash = Crypto.pbkdf2Sync(password, salt, iterations,
    checksum_b64.length, digest);

  return ab64encode(checkHash) === checksum;
}


/**
 * Callback signature for hashPassword
 *
 * @callback hashPassword~cb
 * @param  {Error} err - Error Object
 * @param  {string} hash - The resulting password hash.
 */

/**
 * Callback signature for verifyPassword
 *
 * @callback verifyPassword~cb
 * @param  {Error} err - Error Object
 * @param  {boolean} verified - Whether the password and the hash match.
 */
