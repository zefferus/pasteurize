# Pasteurize

A **secure** password one-way hashing and verification module for Node.js.

[![Build Status](https://travis-ci.org/zefferus/pasteurize.svg?branch=master)](https://travis-ci.org/zefferus/pasteurize) [![Coverage Status](https://coveralls.io/repos/github/zefferus/pasteurize/badge.svg?branch=master)](https://coveralls.io/github/zefferus/pasteurize?branch=master) ![Current Version](https://img.shields.io/npm/v/pasteurize.svg)

Development on **Pasteurize** is sponsored by [Sparo Labs](http://www.sparolabs.com/).

**Pasteurize** helps you create and verify secure password hashes by wrapping the built-in functions of Node.js' [`Crypto` module](https://nodejs.org/dist/latest/docs/api/crypto.html) and making it easier to use. **Pasteurize** uses cryptographically strong pseudo-random data for hash salts and the highly-secure PBKDF2 hashing function to generate a secure one-way hash of your user's password so you do not have to worry about accidentally leaking the original password.

In order to match the signature of the `Crypto` module, **Pasteurize** provides both synchronous and asynchronous methods for generating and verifying password hashes, but it is recommended to use the asynchronous methods as secure password hashing can take a while and the event loop will be blocked during the synchronous methods.


## Install

```bash
$ npm install --save pasteurize
```


## Usage

### `new Pasteurize(keyLength, saltLength, iterations, digest)`

Creates a new `Pasteurize` object where:

- `keyLength` - The desired length of the hashed output.

- `saltLength` - The number of bytes to use for the salt. It is recommended that salts are longer than 16 bytes. See [NIST SP 800-132](http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf) for details.

- `iterations` - The number of iterations to run the PBKDF2 algorithm. The higher the number of iterations, the more secure the derived key will be. According to [NIST SP 800-132](http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf):

    >    A minimum iteration count of 1,000 is recommended. For especially critical keys, or for very powerful systems or systems where user-perceived performance is not critical, an iteration count of 10,000,000 may be appropriate. ... The number of iterations **should** be set as
    high as can be tolerated for the environment, while maintaining acceptable performance.

- `digest` - One of the HMAC digest algorithms supported by Node.js.
    - You can verify which algorithms are supported by your install by running [`crypto.getHashes()`](https://nodejs.org/dist/latest/docs/api/crypto.html#crypto_crypto_gethashes)

Rather than failing later when processing passwords, `Pasteurize` will throw an exception if any of the above arguments are not of the correct type as these are required for proper operation of the PBKDF2 algorithm.

***Security Note:*** Please research the latest security recommendations when establishing your password hashing strategy. New strategies or recommendations may have been published since this document was written that can better help guide your decisions.

```javascript
const Pasteurize = require('pasteurize').Pasteurize;
const pasteurize = new Pasteurize(64, 256, 100000, 'sha512');
```


### `pasteurize.hashPassword(password, [callback])`

Asyncronously generates a password hash based on the initiating values of `Pasteurize` where:

- `password` - The password string to hash.
- `callback` - The optional callback method when password hashing is complete or failed with signature `function (err, [hashedPassword])` where:
    - `err` - Any error condition while creating the password hash.
    - `hashedPassword` - The resulting password hash.

If `callback` is not provided, this method returns a `Promise`.

```javascript
pasteurize.hashPassword('password1', (err, hash) => {
  console.log(hash);
});
// $pbkdf2-sha512$100000$FR0gShfuw07L9.hPZQTN9WEV9osaLEA9dYtOfQNfGUMzzmeAtRqNuu4VNFrya2QlmjT.vChg2FmWLvVYXKnSw1AubMKzRLKYjc3SSxbNClOTTUeIA2WBHG7/QroTCLiKPtUiNZqn9VtwrALkecY0x2wU4mjPqhknbachX752r2/Schh4MPUroSnPZ6ywnkrpNAPgzHT65AMLzjRWKedLfwcQeZ0RClzQjcNsz6BiLNQtz.Hh2IOis7MDWYtgLp1Z347Ru1F9r9nDRcbMadl0.vHCcora3lKVrJvgiv4rWu8pOVtTGq/FECrbsZ12dHW8OeYPwXzKhPxNAf//Gh.oJw$MjNRGhgw7LIoRZYvcdAcUUT22HdMGrg1NHNW7NMQ8HqFVL2vcQCKo0tnEfgBLzAqAiKTBCoAQ4cCUIBnvArGPw
```


### `pasteurize.hashPasswordSync(password)`

Syncronously generates a password hash based on the initiating values of `Pasteurize` where:

- `password` - The password string to hash.

Will throw an exception on any error condition while creating the password hash.

Returns the resulting password hash string.

```javascript
pasteurize.hashPasswordSync('password2');
// `$pbkdf2-sha512$100000$afkU.1uOIs8BuUAFwUE.Fxy9ngEEFLuLE0IN9Pib3lYFEF8TXbgNmUXaaa2DoBYv26BPb6ohObmhiTDAJYiWun5S7ab1jogoN7vvbci1ej.4gw2Dk6746urqx/0Qah5Qafq/t9TRRgMDo7evyuf7pgCIy0I37Q6kX/W9aFWCqW3BP3Z6l.ukuUqBT8YA8eYyUw0Q0DfSBffZ/e2LpeP6xb8IfE2kAHoQHrvmkKNgG3hcH8RS8IXWiQDMaJHIica9zjTWXqEPdagoCj9x/oxkf58jFCYTidmLrwHDSLHPLDWVzcSi05Bu0SWym8Z.T6Wc5ba4hJejhd3JUdgBT./24w$RdmY5JLozECwEeY15/CpbpG6UFQUcULKOB8E.XId6PjP2uv3pDE1kL4Dhyna2xymGKqENOEXHha82TI91AEgIQ`
```

### `pasteurize.verifyPassword(password, hashedPassword, [callback])`

Asynchronously verifies a password against a given hash where:

- `password` - The password string to verify.
- `hashedPassword` - The hashed password against which to verify the password.
- `callback` - The optional callback method when password verification is complete or failed with signature `function(err, [verified])` where:
    - `err` - Any error condition while verifying the password hash.
    - `verified` - Whether the password and the hash match.

If `callback` is not provided, this method returns a `Promise`.

```javascript
pasteurize.hashPassword('password1', (err, hash) => {
  pasteurize.verifyPassword('password1', hash, (err, verified) => {
    console.log(verified);
    // true
  });

  pasteurize.verifyPassword('different password', hash, (err, verified) => {
    console.log(verified);
    // false
  });
});
```


### `pasteurize.verifyPasswordSync(password, hashedPassword)`

Synchronously verifies a password against a given hash where:

- `password` - The password string to verify.
- `hashedPassword` - The hashed password against which to verify the password.

Will throw an exception on any error condition while verifying the password.

Returns whether the password and the hash match.

```javascript
const hash = pasteurize.hashPasswordSync('password1');
pasteurize.verifyPasswordSync('password1', hash);
// true

pasteurize.verifyPasswordSync('different password', hash);
// false
```


## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
