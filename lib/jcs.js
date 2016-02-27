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
/*                              JCS                               */
/*================================================================*/

// Core classes for signing and verification of JSON signatures.

const Crypto = require('crypto');

const Keys = require('./keys');
const ByteArray = require('./bytearray');
const Base64URL = require('./base64url');

const ALGORITHMS = [
    'ES256', 'EC',  'SHA256',
    'ES384', 'EC',  'SHA384',
    'ES512', 'EC',  'SHA512',
    'RS256', 'RSA', 'SHA256',
    'RS384', 'RSA', 'SHA384',
    'RS512', 'RSA', 'SHA512'
];

function findAlgorithm(name) {
  for (var i = 0; i < ALGORITHMS.length; i += 3) {
    if (ALGORITHMS[i] == name) {
      return i;
    }
  }
  throw new TypeError('Unknown signatureAlgorithm: ' + name);
}

function Signature(signatureKey, signatureAlgorithm) {
  this.signatureKey = signatureKey;
  if (signatureKey instanceof Keys.PrivateKey) {
    // Relying on defaults is generally bad, but the following values should be fairly ok :-)
    if (signatureAlgorithm === undefined) {
      signatureAlgorithm = signatureKey.jcs.type == 'EC' ?
 (signatureKey.jcs.curve == 'P-256' ? 'ES256' : 'ES512') : 'RS256';
    }
    var algorithmIndex = findAlgorithm(signatureAlgorithm);
    this.hashAlgorithm = ALGORITHMS[algorithmIndex + 2];
    if (signatureKey.jcs.type != ALGORITHMS[algorithmIndex + 1]) {
      throw new TypeError('Key "' + signatureKey.jcs.type + '" incompatible with algorithm "' + signatureAlgorithm + '"');
    }
    this.signatureAlgorithm = signatureAlgorithm;
  } else {
    throw new TypeError('Key must be "PrivateKey"');
  }
}

Signature.prototype.sign = function(object2Sign) {
  if (typeof object2Sign !== 'object' || Array.isArray(object2Sign)) {
    throw new TypeError('Only "Objects" can be signed');
  }
  if (object2Sign.signature) {
    throw new TypeError('Object is already signed');
  }
  var signature = object2Sign.signature = {};
  signature.algorithm = this.signatureAlgorithm;
  signature.publicKey = this.signatureKey.jcs;
  var signer = Crypto.createSign(this.hashAlgorithm);
  signer.update(ByteArray.stringToUTF8(JSON.stringify(object2Sign)));
  var rawValue = new Buffer(signer.sign(this.signatureKey.pem, 'binary'), 'binary');
  if (this.signatureKey.jcs.type == 'EC') {
    rawValue = Keys.ecDer2Jose(rawValue, this.signatureKey.jcs.curve);
  }
  signature.value = Base64URL.encode(rawValue);
  return object2Sign;
};

exports.Signature = Signature;


