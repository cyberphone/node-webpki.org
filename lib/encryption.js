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

// Class for performing static-ephemeral ECDH operations

const Crypto = require('crypto');

const Keys = require('./keys');
const Util = require('./util');
const ByteArray = require('./bytearray');
const Base64URL = require('./base64url');

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

function ECDH(key) {
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
    jcs.x = Base64URL.encode(publicKeyBlob.subarray(1, 1 + coordinateLength)),
    jcs.y = Base64URL.encode(publicKeyBlob.subarray(1 + coordinateLength));
    this.publicKey = Keys.encodePublicKey(jcs);
  } else {
    throw new TypeError('Argument must be "PrivateKey" or "PublicKey"');
  }
  this.curve = key.jcs.curve;
}

ECDH.prototype.getPublicKey = function() {
  if (this.ephemeralMode) {
    return this.publicKey;
  }
  throw new TypeError('Not applicable to ECDH(PrivateKey)');
};

ECDH.prototype.computeZ = function(publicKey) {
  if (publicKey instanceof Keys.PublicKey) {
    getAlgorithmId(publicKey);
    if (this.curve != publicKey.jcs.curve) {
      throw new TypeError('"PublicKey" curve does not match ECDH curve')
    }
    return new Uint8Array(this.ecdh.computeSecret(publicKey.ecPublicKeyBlob));
  }
  throw new TypeError('Argument must be a "PublicKey"');
};

ECDH.prototype.computeWithKDF = function(publicKey, dataEncryptionAlgorithm) {
  if (dataEncryptionAlgorithm === undefined) {
    throw new TypeError('Missing "dataEncryptionAlgorithm"');
  }
  var Z = this.computeZ(publicKey);
  var hash = Crypto.createHash('sha256');
  // Round 1 indicator
  hash.update(new Uint8Array([0,0,0,1]));
  // Z
  hash.update(Z);
  // AlgorithmID = Content encryption algorithm
  hash.update(new Uint8Array([0,0,0,dataEncryptionAlgorithm.length]));
  hash.update(ByteArray.stringToUTF8(dataEncryptionAlgorithm));
  // PartyUInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // PartyVInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // SuppPubInfo = Key length in bits
  hash.update(new Uint8Array([0,0,1,0]));
  return new Uint8Array(hash.digest());
};

/*
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", "BC");
        // Round 1 indicator
        addInt4(messageDigest, 1);
        // Z
        messageDigest.update(keyAgreement.generateSecret());
        // AlgorithmID = Content encryption algorithm
        addInt4(messageDigest, dataEncryptionAlgorithm.length());
        messageDigest.update(dataEncryptionAlgorithm.getBytes("UTF-8"));
        // PartyUInfo = Empty
        addInt4(messageDigest, 0);
        // PartyVInfo = Empty
        addInt4(messageDigest, 0);
        // SuppPubInfo = Key length in bits
        addInt4(messageDigest, 256);
        return messageDigest.digest();
*/

exports.ECDH = ECDH;
