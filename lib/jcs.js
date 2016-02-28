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
    'SH256', null,  'sha256',
    'SH384', null,  'sha384',
    'SH512', null,  'sha512',
    'ES256', 'EC',  'sha256',
    'ES384', 'EC',  'sha384',
    'ES512', 'EC',  'sha512',
    'RS256', 'RSA', 'sha256',
    'RS384', 'RSA', 'sha384',
    'RS512', 'RSA', 'sha512'
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

function checkForSignature(jcsObject) {
  // JCS does not permit signing of top level [] only {}
  if (typeof jcsObject !== 'object' || Array.isArray(jcsObject)) {
    throw new TypeError('Top level element must be an "Object"');
  }
  return jcsObject.signature !== undefined;
}

function Signer(signatureKey, signatureAlgorithm) {
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

Signer.prototype.sign = function(object2Sign) {
  if (checkForSignature(object2Sign)) {
    throw new TypeError('Object is already signed');
  }
  var signature = object2Sign.signature = {};
  var signatureValue;
  signature.algorithm = this.signatureAlgorithm;
  if (this.signatureKey instanceof Keys.PrivateKey) {
    if (this.certificatePath === undefined) {
      signature.publicKey = this.signatureKey.jcs;
    } else {
      if (this.signerCertificateFlag) {
        var signerCertificate = signature.signerCertificate = {};
        signerCertificate.issuer = this.certificatePath[0].getIssuer();
        signerCertificate.serialNumber = this.certificatePath[0].getSerialNumber().toString();
        signerCertificate.subject = this.certificatePath[0].getSubject();
      }
      signature.certificatePath = [];
      for (var q = 0; q < this.certificatePath.length; q++) {
        signature.certificatePath.push(Base64URL.encode(this.certificatePath[q].getCertificateBlob()));
      }
    }
    var signer = Crypto.createSign(this.hashAlgorithm);
    // Canonicalization? Using ES6/V8 it JustWorks(tm) out of the box!
    signer.update(ByteArray.stringToUTF8(JSON.stringify(object2Sign)));
    signatureValue = new Buffer(signer.sign(this.signatureKey.pem, 'binary'), 'binary');
    // There are (of course) two "standard" ways of representing ECDSA signatures... 
    if (this.signatureKey.jcs.type == 'EC') {
      signatureValue = Keys.ecDer2JoseSignature(signatureValue, this.signatureKey.jcs.curve);
    }
  } else {
    throw new TypeError('Not implemented');
  }
  signature.value = Base64URL.encode(signatureValue);
  return object2Sign;
};

Signer.prototype.setCertificatePath = function(certificatePath, signerCertificateFlag){
  this.certificatePath = certificatePath;
  this.signerCertificateFlag = signerCertificateFlag;
  if (certificatePath === undefined || !Array.isArray(certificatePath) ||
      certificatePath.length == 0 || !(certificatePath[0] instanceof Keys.Certificate)) {
    throw new TypeError('Invalid certificate path');
  }
  if (this.signatureKey instanceof Keys.PrivateKey) {
    if (!this.signatureKey.getPublicKey().equals(certificatePath[0].getPublicKey())) {
      throw new TypeError('Signer certificate doesn\'t match "PrivateKey"');
    }
  } else {
    throw new TypeError('Missing "PrivateKey"');
  }
};

function DecodedSignature() {
}

DecodedSignature.prototype.getPublicKey = function() {
  if (this.publicKey === undefined) {
    throw new TypeError('No "publicKey" present');
  }
  return this.publicKey;
}

DecodedSignature.prototype.getCertificatePath = function() {
  if (this.certificatePath === undefined) {
    throw new TypeError('No "certificatePath" present');
  }
  return this.certificatePath;
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
    var publicKey;
    if (clone.certificatePath === undefined) {
      decodedSignature.publicKey = publicKey = Keys.encodePublicKey(clone.publicKey);
    } else {
      if (!Array.isArray(clone.certificatePath) || clone.certificatePath.length == 0) {
        throw new TypeError('Bad format for "certificatePath"');
      }
      decodedSignature.certificatePath = [];
      for (var q = 0; q < clone.certificatePath.length; q++) {
        decodedSignature.certificatePath.push(new Keys.Certificate(Base64URL.decode(clone.certificatePath[q])));
      }
      var signerCertificate = decodedSignature.certificatePath[0];
      publicKey = signerCertificate.getPublicKey();
      if (clone.signerCertificate) {
        if (Util.getPropertyUnconditionally(clone.signerCertificate,'issuer') !=
              signerCertificate.getIssuer() ||
            Util.getPropertyUnconditionally(clone.signerCertificate,'serialNumber') !=
              signerCertificate.getSerialNumber().toString() ||
            Util.getPropertyUnconditionally(clone.signerCertificate,'subject') !=
              signerCertificate.getSubject()) {
          throw new TypeError('Non-matching "signerCertificate" properties');
        }
      }
    }
    var hashAlgorithm = getHashAlgorithm(publicKey.jcs.type, signatureAlgorithm);
    // There are (of course) two "standard" ways of representing ECDSA signatures... 
    if (publicKey.jcs.type == 'EC') {
      signatureValue = Keys.ecJose2DerSignature(signatureValue, publicKey.jcs.curve);
    }
    var verifier = Crypto.createVerify(hashAlgorithm);
    verifier.update(signedData);
    if (!verifier.verify(publicKey.pem, signatureValue)) {
      throw new TypeError('Signature did not verify: ' + JSON.stringify(clone));
    }
  } else {
    throw new TypeError('Not implemented yet');
  }
  return decodedSignature;
}

exports.Signer = Signer;
exports.Verifier = Verifier;
