/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
 
'use strict';

/*================================================================*/
/*                             Encryption                         */
/*================================================================*/

// Class for performing:
// - Static-ephemeral ECDH operations
// - Symmetric-key encryption/decryption operations

const Crypto = require('crypto');

const Keys = require('./keys');
const ByteArray = require('./bytearray');
const Base64Url = require('./base64url');
const Random = require('./random');

const JOSE_A128CBC_HS256_ALG_ID  = 'A128CBC-HS256';

function checkEncryptionAlgorithm(encryptionAlgorithm) {
  if (encryptionAlgorithm === undefined) {
    throw new TypeError('Missing "encryptionAlgorithm"');
  }
  if (encryptionAlgorithm != JOSE_A128CBC_HS256_ALG_ID) {
    throw new TypeError('Unsupported "encryptionAlgorithm"');
  }
}

function getTag(key, cipherText, iv, authenticatedData) {
  if (key.length != 32) {
    throw new TypeError('Unexpected key length: ' + key.length);
  }
  if (iv.length != 16) {
    throw new TypeError('Unexpected iv length: ' + iv.length);
  }
  var al = new Uint8Array(8);
  var value = authenticatedData.length * 8;
  for (var q = 24, i = 4; q >= 0; q -= 8, i++) {
      al[i] = value >>> q;
  }
  var hmac = Crypto.createHmac('SHA256', key.subarray(0, 16));
  hmac.update(authenticatedData);
  hmac.update(iv);
  hmac.update(cipherText);
  hmac.update(al);
  return new Uint8Array(hmac.digest()).subarray(0, 16);
}

function contentEncryption(dataEncryptionAlgorithm, 
                           key,
                           plainText,
                           authenticatedData) {
  checkEncryptionAlgorithm(dataEncryptionAlgorithm);
  var iv = Random.generateRandomNumber(16);
  var cipher = Crypto.createCipheriv('AES-128-CBC', key.subarray(16), iv);
  var partial = new Uint8Array(cipher.update(plainText));
  var cipherText = ByteArray.add(partial, new Uint8Array(cipher.final()));
  return { cipherText: cipherText, iv: iv, tag: getTag(key, cipherText, iv, authenticatedData) };
}

function generateDataEncryptionKey(dataEncryptionAlgorithm) {
  checkEncryptionAlgorithm(dataEncryptionAlgorithm);
  return Random.generateRandomNumber(32);
}

function contentDecryption(dataEncryptionAlgorithm,
                           key,
                           cipherText,
                           iv,
                           authenticatedData,
                           tag) {
  checkEncryptionAlgorithm(dataEncryptionAlgorithm);
  if (!ByteArray.equals(tag, getTag(key, cipherText, iv, authenticatedData))) {
    throw new TypeError('Authentication error on algorithm: ' + dataEncryptionAlgorithm);
  }
  var cipher = Crypto.createDecipheriv('AES-128-CBC', key.subarray(16), iv);
  var partial = new Uint8Array(cipher.update(cipherText));
  return ByteArray.add(partial, new Uint8Array(cipher.final()));
}
 

const CURVE_TO_INTERNAL_ALGORITHM_ID = [
    'P-256', 'prime256v1',
    'P-384', 'secp384r1',
    'P-521', 'secp521r1'
];

function getAlgorithmId(key) {
  if (key.jcs.type != 'EC') {
    throw new TypeError('Not "EC" key');
  }
  for (var i = 0; i < CURVE_TO_INTERNAL_ALGORITHM_ID.length; i += 2) {
    if (key.jcs.curve == CURVE_TO_INTERNAL_ALGORITHM_ID[i]) {
      return CURVE_TO_INTERNAL_ALGORITHM_ID[i + 1];
    }
  }
  throw new TypeError('No algorithm for curve: ' + key.jcs.curve);
}

function Ecdh(key) {
  if (key instanceof Keys.PrivateKey) {
    this.ephemeralMode = false;
    this.ecdh = Crypto.createECDH(getAlgorithmId(key));
    this.ecdh.setPrivateKey(key.ecPrivateKeyBlob, 'binary');
  } else if (key instanceof Keys.PublicKey) {
    this.ephemeralMode = true;
    this.ecdh = Crypto.createECDH(getAlgorithmId(key));
    var publicKeyBlob = new Uint8Array(this.ecdh.generateKeys());
    if (publicKeyBlob.length != key.ecPublicKeyBlob.length) {
      throw new TypeError('Unexpected public key length');
    }
    var coordinateLength = (publicKeyBlob.length - 1) / 2;
    var jcs = Object.assign({}, key.jcs);
    jcs.x = Base64Url.encode(publicKeyBlob.subarray(1, 1 + coordinateLength)),
    jcs.y = Base64Url.encode(publicKeyBlob.subarray(1 + coordinateLength));
    this.publicKey = Keys.encodePublicKey(jcs);
  } else {
    throw new TypeError('Argument must be "PrivateKey" or "PublicKey"');
  }
  this.curve = key.jcs.curve;
}

Ecdh.prototype.getPublicKey = function() {
  if (this.ephemeralMode) {
    return this.publicKey;
  }
  throw new TypeError('Not applicable to Ecdh(PrivateKey)');
};

Ecdh.prototype.computeZ = function(publicKey) {
  if (publicKey instanceof Keys.PublicKey) {
    getAlgorithmId(publicKey);
    if (this.curve != publicKey.jcs.curve) {
      throw new TypeError('"PublicKey" curve does not match Ecdh curve')
    }
    return new Uint8Array(this.ecdh.computeSecret(publicKey.ecPublicKeyBlob));
  }
  throw new TypeError('Argument must be a "PublicKey"');
};

Ecdh.prototype.computeWithKdf = function(publicKey, encryptionAlgorithm) {
  checkEncryptionAlgorithm(encryptionAlgorithm);
  var Z = this.computeZ(publicKey);
  var hash = Crypto.createHash('SHA256');
  // Round 1 indicator
  hash.update(new Uint8Array([0,0,0,1]));
  // Z
  hash.update(Z);
  // AlgorithmID = Content encryption algorithm
  hash.update(new Uint8Array([0,0,0,encryptionAlgorithm.length]));
  hash.update(ByteArray.stringToUtf8(encryptionAlgorithm));
  // PartyUInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // PartyVInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // SuppPubInfo = Key length in bits
  hash.update(new Uint8Array([0,0,1,0]));
  return new Uint8Array(hash.digest());
};

exports.Ecdh = Ecdh;
exports.JOSE_A128CBC_HS256_ALG_ID = JOSE_A128CBC_HS256_ALG_ID;
exports.contentEncryption = contentEncryption;
exports.contentDecryption = contentDecryption;
exports.generateDataEncryptionKey = generateDataEncryptionKey;
