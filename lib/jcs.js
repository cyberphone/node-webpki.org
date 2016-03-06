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

// Core classes for signing and verification of JSON signatures
// using the JCS (JSON Cleartext Signature) scheme.

const Crypto = require('crypto');

const Keys = require('./keys');
const Util = require('./util');
const ByteArray = require('./bytearray');
const Base64URL = require('./base64url');

const ALGORITHMS = [
    'HS256', null,  'sha256',
    'HS384', null,  'sha384',
    'HS512', null,  'sha512',
    'ES256', 'EC',  'sha256',
    'ES384', 'EC',  'sha384',
    'ES512', 'EC',  'sha512',
    'RS256', 'RSA', 'sha256',
    'RS384', 'RSA', 'sha384',
    'RS512', 'RSA', 'sha512'
];

const SIGNATURE_TYPE = {
    PKI        : 0,
    HMAC       : 1,
    PUBLIC_KEY : 2
};


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

function getHMACKey(hmacKey) {
  if (typeof hmacKey == 'string') {
    hmacKey = ByteArray.stringToUTF8(hmacKey);
  } else if (!(hmacKey instanceof Uint8Array)) {
    throw new TypeError('HMAC keys must be "String" or "Uint8Array"');
  }
  return hmacKey;
}

function Signer(signatureKey, signatureAlgorithm) {
  this._used = false;
  if (signatureKey instanceof Keys.PrivateKey) {
    this.signatureKey = signatureKey;
    // Relying on defaults is generally bad, but the following values should be fairly ok :-)
    if (signatureAlgorithm === undefined) {
      signatureAlgorithm = signatureKey.jcs.type == 'EC' ?
 (signatureKey.jcs.curve == 'P-256' ? 'ES256' : 'ES512') : 'RS256';
    }
    this.hashAlgorithm = getHashAlgorithm(signatureKey.jcs.type, signatureAlgorithm);
    this._localSigner = this._asymmetricKeySign;
  } else {
    this.signatureKey = getHMACKey(signatureKey);
    if (signatureAlgorithm === undefined) {
      throw new TypeError('HMAC signatures must have a specified signature algorithm');
    }
    var i = findAlgorithm(signatureAlgorithm);
    if (ALGORITHMS[i + 1]) {
      throw new TypeError('Invalid HMAC algorithm: ' +  signatureAlgorithm);
    }
    this.hashAlgorithm = ALGORITHMS[i + 2];
    this._localSigner = this._symmetricKeySign;
  }
  this.signatureAlgorithm = signatureAlgorithm;
  return this;
}

Signer.prototype._asymmetricKeySign = function(data2Sign) {
  var signer = Crypto.createSign(this.hashAlgorithm);
  signer.update(data2Sign);
  var signatureValue = signer.sign(this.signatureKey.pem);
  // There are (of course) two "standard" ways of representing ECDSA signatures... 
  if (this.signatureKey.jcs.type == 'EC') {
    signatureValue = Keys.ecDer2JoseSignature(signatureValue, this.signatureKey.jcs.curve);
  }
  return signatureValue;
};

Signer.prototype._symmetricKeySign = function(data2Sign) {
  var signer = Crypto.createHmac(this.hashAlgorithm, this.signatureKey);
  signer.update(data2Sign);
  return signer.digest();
};

Signer.prototype.sign = function(object2Sign) {
  if (checkForSignature(object2Sign)) {
    throw new TypeError('Object is already signed');
  }
  if (this._used) {
    throw new TypeError('You can only call sign() once per instantiation');
  }
  this._used = true;
  var signature = object2Sign.signature = {};
  var signatureValue;
  signature.algorithm = this.signatureAlgorithm;
  if (this.keyId !== undefined) {
    signature.keyId = this.keyId;
  }
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
  }
  // Canonicalization anybody? Using ES6/V8 it JustWorks(tm) out of the box!
  signature.value = Base64URL.encode(this._localSigner(ByteArray.stringToUTF8(JSON.stringify(object2Sign))));
  return object2Sign;
};

Signer.prototype.setCertificatePath = function(certificatePath, signerCertificateFlag){
  this.signerCertificateFlag = signerCertificateFlag;
  this.certificatePath = Keys.checkCertificatePath(certificatePath);
  if (this.signatureKey instanceof Keys.PrivateKey) {
    if (!this.signatureKey.getPublicKey().equals(certificatePath[0].getPublicKey())) {
      throw new TypeError('Signer certificate doesn\'t match "PrivateKey"');
    }
  } else {
    throw new TypeError('Missing "PrivateKey"');
  }
  return this;
};

Signer.prototype.setKeyId = function(keyId){
  this.keyId = keyId;
  return this;
};

function DecodedSignature() {
}

DecodedSignature.prototype.getPublicKey = function() {
  if (this.publicKey === undefined) {
    throw new TypeError('No "publicKey" present');
  }
  return this.publicKey;
};

DecodedSignature.prototype.getCertificatePath = function() {
  if (this.certificatePath === undefined) {
    throw new TypeError('No "certificatePath" present');
  }
  return this.certificatePath;
};

DecodedSignature.prototype.verifyPublicKey = function(publicKey) {
  return this.getPublicKey().equals(publicKey);
};

DecodedSignature.prototype.isTrusted = function(trustList) {
  if (this.certificatePath === undefined) {
    throw new TypeError('Not a PKI signature');
  }
  for (var q = 0; q < trustList.length; q++) {
    if (this.certificatePath[this.certificatePath.length - 1].isSignedBy(trustList[q]) ||
        ByteArray.equals(this.certificatePath[this.certificatePath.length - 1].certificateBlob,
                         trustList[q].certificateBlob)) {
      return true;
    }
  }
  return false;
};

DecodedSignature.prototype.verifyHmac = function(hmacKey) {
  var verifier = Crypto.createHmac(ALGORITHMS[findAlgorithm(this.signatureAlgorithm) + 2],
                                   getHMACKey(hmacKey));
  verifier.update(this.signedData);
  return ByteArray.equals(verifier.digest(), this.signatureValue);
};

DecodedSignature.prototype.getSignatureType = function() {
  if (this.publicKey !== undefined) {
    return SIGNATURE_TYPE.PUBLIC_KEY;
  }
  if (this.certificatePath !== undefined) {
    return SIGNATURE_TYPE.PKI;
  }
  return SIGNATURE_TYPE.HMAC;
};

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
  var signatureValue = Base64URL.decode(Util.getStringUnconditionally(clone, 'value'));
  // Remove signature "value" property from the "signature" element
  delete signedObject.signature.value;
  // Get a "normalized" rather than "canonicalized" JSON string (=signed data).
  var signedData = ByteArray.stringToUTF8(JSON.stringify(signedObject));
  // Restore signed object
  signedObject.signature = clone;
  // We should always have an algorithm property
  var signatureAlgorithm = Util.getStringUnconditionally(clone, 'algorithm');
  decodedSignature.signatureAlgorithm = signatureAlgorithm;
  // We do not allow anything unknown within a signature object
  var propertyCount = 2;  // "algorithm" and "value" are mandatory
  // An optional "keyId" should be catered for
  if (clone.keyId !== undefined) {
    decodedSignature.keyId = Util.getStringUnconditionally(clone, 'keyId');
    propertyCount++;
  }
  // Now verify public key signatures for technical correctness
  if (ALGORITHMS[findAlgorithm(signatureAlgorithm) + 1]) {
    var publicKey;
    if (clone.certificatePath === undefined) {
      decodedSignature.publicKey =
        publicKey = Keys.encodePublicKey(Util.getObjectUnconditionally(clone,'publicKey'));
      propertyCount++;
    } else {
      var certificatePath = Util.getArrayUnconditionally(clone, 'certificatePath');
      if (certificatePath.length == 0) {
        throw new TypeError('Empty "certificatePath" not allowed');
      }
      propertyCount++;
      decodedSignature.certificatePath = [];
      for (var q = 0; q < certificatePath.length; q++) {
        decodedSignature.certificatePath.push(new Keys.Certificate(Base64URL.decode(certificatePath[q])));
      }
      var signatureCertificate = Keys.checkCertificatePath(decodedSignature.certificatePath)[0];
      publicKey = signatureCertificate.getPublicKey();
      if (clone.signerCertificate !== undefined) {
        var certificateProperties = Util.getObjectUnconditionally(clone, 'signerCertificate');
        if (Util.getStringUnconditionally(certificateProperties, 'issuer') !=
              signatureCertificate.getIssuer() ||
            Util.getStringUnconditionally(certificateProperties, 'serialNumber') !=
              signatureCertificate.getSerialNumber().toString() ||
            Util.getStringUnconditionally(certificateProperties, 'subject') !=
              signatureCertificate.getSubject()) {
          throw new TypeError('Non-matching "signerCertificate" properties');
        }
        Util.checkForUnexpected(certificateProperties, 3);
        propertyCount++;
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
    decodedSignature.signedData = signedData;
    decodedSignature.signatureValue = signatureValue;
  }
  Util.checkForUnexpected(clone, propertyCount);
  return decodedSignature;
};

exports.Signer = Signer;
exports.Verifier = Verifier;
exports.SIGNATURE_TYPE = SIGNATURE_TYPE;
