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
const Util = require('./util');
const ByteArray = require('./bytearray');
const Base64URL = require('./base64url');

const ALGORITHMS = [
    'SH256', null,  'SHA256',
    'SH384', null,  'SHA384',
    'SH512', null,  'SHA512',
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

function getHashAlgorithm(keyType, signatureAlgorithm) {
  var algorithmIndex = findAlgorithm(signatureAlgorithm);
  if (keyType != ALGORITHMS[algorithmIndex + 1]) {
    throw new TypeError('Key "' + keyType + '" incompatible with algorithm "' + signatureAlgorithm + '"');
  }
  return ALGORITHMS[algorithmIndex + 2];
}

function Signature(signatureKey, signatureAlgorithm) {
  this.signatureKey = signatureKey;
  if (signatureKey instanceof Keys.PrivateKey) {
    // Relying on defaults is generally bad, but the following values should be fairly ok :-)
    if (signatureAlgorithm === undefined) {
      signatureAlgorithm = signatureKey.jcs.type == 'EC' ?
 (signatureKey.jcs.curve == 'P-256' ? 'ES256' : 'ES512') : 'RS256';
    }
    this.hashAlgorithm = getHashAlgorithm(signatureKey.jcs.type, signatureAlgorithm);
    this.signatureAlgorithm = signatureAlgorithm;
  } else {
    throw new TypeError('Key must be "PrivateKey"');
  }
}

function checkForSignature(jcsObject) {
  // JCS does not permit signing of top level [] only {}
  if (typeof jcsObject !== 'object' || Array.isArray(jcsObject)) {
    throw new TypeError('Top level element must be an "Object"');
  }
  return jcsObject.signature !== undefined;
}

Signature.prototype.sign = function(object2Sign) {
  if (checkForSignature(object2Sign)) {
    throw new TypeError('Object is already signed');
  }
  var signature = object2Sign.signature = {};
  signature.algorithm = this.signatureAlgorithm;
  signature.publicKey = this.signatureKey.jcs;
  var signer = Crypto.createSign(this.hashAlgorithm);
  // Canonicalization? Using ES6/V8 it JustWorks(tm) out of the box!
  signer.update(ByteArray.stringToUTF8(JSON.stringify(object2Sign)));
  var signatureValue = new Buffer(signer.sign(this.signatureKey.pem, 'binary'), 'binary');
  // There are (of course) two "standard" ways of representing ECDSA signatures... 
  if (this.signatureKey.jcs.type == 'EC') {
    signatureValue = Keys.ecDer2JoseSignature(signatureValue, this.signatureKey.jcs.curve);
  }
  signature.value = Base64URL.encode(signatureValue);
  return object2Sign;
};

function DecodedSignature() {
}

DecodedSignature.prototype.getPublicKey = function() {
  if (this.publicKey === undefined) {
    throw new TypeError('No "PublicKey" present');
  }
  return this.publicKey;
}

DecodedSignature.prototype.verifyPublicKey = function(publicKey) {
  return this.getPublicKey().equals(publicKey);
}

function Verifier() {
}

Verifier.prototype.decodeSignature = function(signedObject) {
  var decodedSignature = new DecodedSignature();
  if (!checkForSignature(signedObject)) {
    throw new TypeError('Object is not signed');
  }
  // Clone "signature" child object
  var clone = Object.assign({}, signedObject.signature);
  // Get signature value
  var signatureValue = Base64URL.decode(Util.getPropertyUnconditionally(clone, 'value'));
  // Remove signature "value" property from the "signature" element
  delete signedObject.signature.value;
  // Get normalized JSON string (signed data)
  var signedData = ByteArray.stringToUTF8(JSON.stringify(signedObject));
  // Restore signed object
  signedObject.signature = clone;
  // We should always have an algorithm property
  var signatureAlgorithm = Util.getPropertyUnconditionally(clone, 'algorithm');
  decodedSignature.signatureAlgorithm = signatureAlgorithm;
  // Now verify public key signatures for technical correctness
  if (ALGORITHMS[findAlgorithm(signatureAlgorithm) + 1]) {
    this.publicKey = Keys.encodePublicKey(clone.publicKey);
    var hashAlgorithm = getHashAlgorithm(this.publicKey.jcs.type, signatureAlgorithm);
    // There are (of course) two "standard" ways of representing ECDSA signatures... 
    if (this.publicKey.jcs.type == 'EC') {
      signatureValue = Keys.ecJose2DerSignature(signatureValue, this.publicKey.jcs.curve);
    }
    var verifier = Crypto.createVerify(hashAlgorithm);
    verifier.update(signedData);
    if (!verifier.verify(this.publicKey.pem, signatureValue)) {
      throw new TypeError('Signature did not verify: ' + JSON.stringify(clone));
    }
  } else {
    throw new TypeError('Not implemented yet');
  }
  decodedSignature.publicKey = this.publicKey;
  return decodedSignature;
}


exports.Signature = Signature;
exports.Verifier = Verifier;
