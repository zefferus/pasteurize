import Crypto = require('crypto');

interface HashComponents {
  digest: string,
  iterations: number,
  salt: Buffer,
  checksum: string,
  checksum_b64: Buffer
};

export class Pasteurize {

  constructor(private keyLength: number, private saltLength: number,
    private iterations: number, private digest: string) {

    if (keyLength === null || keyLength < 0) {
      throw new TypeError('Key Length must be a non-negative number');
    }
    if (saltLength === null || saltLength < 0) {
      throw new TypeError('Salt Length must be a non-negative number');
    }
    if (iterations === null || iterations < 0) {
      throw new TypeError('Iterations must be a non-negative number');
    }
    if (Crypto.getHashes().indexOf(digest) < 0) {
      throw new TypeError('Unsupported digest type');
    }
  }


  hashPassword(password: string, cb?: (err: Error, hash?: string) => void): Promise<string> {
    const promise = new Promise((resolve, reject) => {

      Crypto.randomBytes(this.saltLength, (err: Error, salt: Buffer) => {

        if (err) {
          return reject(err);
        }

        return Crypto.pbkdf2(password, salt, this.iterations, this.keyLength, this.digest,
        (err: Error, key: Buffer) => {

          if (err) {
            return reject(err);
          }

          return resolve(makeHashString(this.digest, this.iterations, salt, key));
        });
      });
    });

    if (cb) {
      promise.then((hash: string) => {
        cb(null, hash);
      })
      .catch((e) => {
        cb(e);
      });

      return;
    }

    return promise;
  }


  hashPasswordSync(password: string): string {

    const salt = Crypto.randomBytes(this.saltLength);
    const hash = Crypto.pbkdf2Sync(password, salt, this.iterations, this.keyLength, this.digest);

    return makeHashString(this.digest, this.iterations, salt, hash);
  }


  verifyPassword(password: string, hashedPassword: string,
    cb?: (err: Error, matches?: boolean) => void): Promise<boolean> {

    const promise = new Promise((resolve: (verified: boolean) => any,
      reject: (err: Error) => any) => {

      const hashComponents = extractHashComponents(hashedPassword);

      if (!hashComponents) {
        return resolve(false);
      }

      const {
        digest,
        iterations,
        salt,
        checksum,
        checksum_b64
      } = hashComponents;

      Crypto.pbkdf2(password, salt, iterations, checksum_b64.length, digest, (err, checkHash) => {
        if (err) {
          return reject(err);
        }

        return resolve(ab64encode(checkHash) === checksum);
      });
    });

    if (cb) {
      promise.then((matches: boolean) => {
        cb(null, matches);
      })
      .catch((e) => {
        cb(e);
      });

      return;
    }

    return promise;
  }


  verifyPasswordSync(password: string, hashedPassword: string): boolean {

    const hashComponents = extractHashComponents(hashedPassword);

    if (!hashComponents) {
      return false;
    }

    const {
      digest,
      iterations,
      salt,
      checksum,
      checksum_b64
    } = hashComponents;

    // verify the salt and hash against the password
    const checkHash = Crypto.pbkdf2Sync(password, salt, iterations,
      checksum_b64.length, digest);

    return ab64encode(checkHash) === checksum;
  }
}



// Private methods

// *****************************************************************************
// Note: The following private methods are to ensure compatibility with Python's
// passlib (https://bitbucket.org/ecollins/passlib/) and the way it generates
// hashes.
// *****************************************************************************

// Converts a Buffer to an adapted-base64 string
function ab64encode(buffer: Buffer): string {
  return buffer.toString('base64').replace(/\+/g, '.').replace(/\=+$/, '');
}

// Converts an adapted-base64 string to a Buffer
function ab64decode(data: string): Buffer {

  // We have to look at the last set of 4 bytes
  const offset = data.length & 3;

  if (offset === 1) {
    // We should never end up with two bytes of offset after padding is removed
    throw new Error('invalid base64 input');
  }

  let padding = '';

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
function makeHashString(digest: string, iterations: number, salt: Buffer, encoded: Buffer): string {
  return [
    `$pbkdf2-${ digest }`,
    iterations,
    ab64encode(salt),
    ab64encode(encoded)
  ].join('$');
}

// Parses the components of a passlib hash
function parseHashString(hash: string): string[] {
  return hash.match(/^\$pbkdf2-(\w+)\$(\d+)\$([A-Za-z0-9\.\/]+)\$([A-Za-z0-9\.\/]+$)/);
}


// Extracts the components of a hash into usable form
function extractHashComponents(hash: string): HashComponents {

  const match = parseHashString(hash);

  if (!match || !match.length) {
    return null;
  }

  const digest = match[1];

  if (Crypto.getHashes().indexOf(digest) < 0) {
    throw new TypeError('Unsupported digest');
  }

  const iterations = parseInt(match[2], 10),
    salt = ab64decode(match[3]),
    checksum = match[4],
    checksum_b64 = ab64decode(checksum);

  return {
    digest,
    iterations,
    salt,
    checksum,
    checksum_b64
  };
}
