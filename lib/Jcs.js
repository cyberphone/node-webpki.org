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
/*                              Jcs                               */
/*================================================================*/

// Core classes for signing and verification of JSON signatures
// using the JCS (JSON Cleartext Signature) scheme.

const Crypto = require('crypto');

const Keys = require('./Keys');
const JsonUtil = require('./JsonUtil');
const ByteArray = require('./ByteArray');
const Base64Url = require('./Base64Url');

    // Arguments
const EC_PUBLIC_KEY           = 'EC';
const RSA_PUBLIC_KEY          = 'RSA';
const SIGNATURE_VERSION_ID    = 'http://xmlns.webpki.org/jcs/v1';
    
    // JSON properties
const ALGORITHM_JSON          = 'algorithm';
const CURVE_JSON              = 'curve';
const E_JSON                  = 'e';
const EXTENSIONS_JSON         = 'extensions';
const ISSUER_JSON             = 'issuer';
const KEY_ID_JSON             = 'keyId';
const N_JSON                  = 'n';
const PUBLIC_KEY_JSON         = 'publicKey';
const SERIAL_NUMBER_JSON      = 'serialNumber';
const SIGNATURE_JSON          = 'signature';
const SIGNER_CERTIFICATE_JSON = 'signerCertificate';
const SUBJECT_JSON            = 'subject';
const TYPE_JSON               = 'type';
const PEM_URL_JSON            = 'pemUrl';
const VALUE_JSON              = 'value';
const VERSION_JSON            = 'version';
const X_JSON                  = 'x';
const CERTIFICATE_PATH_JSON   = 'certificatePath';
const Y_JSON                  = 'y';

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
  // JCS does not permit signing of top level [], only {}
  if (typeof jcsObject !== 'object' || Array.isArray(jcsObject)) {
    throw new TypeError('Top level element must be an "Object"');
  }
  return jcsObject[SIGNATURE_JSON] !== undefined;
}

function getHmacKey(hmacKey) {
  if (typeof hmacKey == 'string') {
    hmacKey = ByteArray.stringToUtf8(hmacKey);
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
    this.signatureKey = getHmacKey(signatureKey);
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
  var signatureValue;
  if (checkForSignature(object2Sign)) {
    throw new TypeError('Object is already signed');
  }
  if (this._used) {
    throw new TypeError('You can only call sign() once per instantiation');
  }
  this._used = true;
  var writer = new JsonUtil.ObjectWriter(object2Sign);
  var signatureWriter = writer.setObject('signature');
  signatureWriter.setString(ALGORITHM_JSON, this.signatureAlgorithm);
  if (this.keyId !== undefined) {
    signatureWriter.setString(KEY_ID_JSON, this.keyId);
  }
  if (this.signatureKey instanceof Keys.PrivateKey) {
    if (this.certificatePath === undefined) {
      signatureWriter.setPublicKey(this.signatureKey.getPublicKey());
    } else {
      if (this.signerCertificateFlag) {
        signatureWriter.setObject(SIGNER_CERTIFICATE_JSON, new JsonUtil.ObjectWriter()
          .setString(ISSUER_JSON, this.certificatePath[0].getIssuer())
          .setBigInteger(SERIAL_NUMBER_JSON, this.certificatePath[0].getSerialNumber())
          .setString(SUBJECT_JSON, this.certificatePath[0].getSubject()));
      }
      var arrayWriter = signatureWriter.setArray(CERTIFICATE_PATH_JSON);
      this.certificatePath.forEach((certificate) => {
        arrayWriter.setBinary(certificate.getCertificateBlob());
      });
    }
  }
  signatureWriter.setBinary(VALUE_JSON, this._localSigner(writer.getNormalizedData()));
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
                                   getHmacKey(hmacKey));
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
  // We do not allow anything unknown within a signature object
  var reader = new JsonUtil.ObjectReader(signedObject, SIGNATURE_JSON);
  if (reader.hasProperty(VERSION_JSON)) {
    if (reader.getString(VERSION_JSON) != SIGNATURE_VERSION_ID) {
      throw new TypeError('Unknown signature version');
    }
  }
  // Clone "signature" child object
  var clone = Object.assign({}, signedObject.signature);
  // Get signature value
  var signatureValue = reader.getBinary(VALUE_JSON);
  // Remove signature "value" property from the "signature" element
  delete signedObject.signature.value;
  // Get a "normalized" rather than "canonicalized" JSON string (=signed data).
  var signedData = JsonUtil.getNormalizedData(signedObject);
  // Restore signed object
  signedObject.signature = clone;
  // We should always have an algorithm property
  decodedSignature.signatureAlgorithm = reader.getString(ALGORITHM_JSON);
  // An optional "keyId" should be catered for
  if (reader.hasProperty(KEY_ID_JSON)) {
    decodedSignature.keyId = reader.getString(KEY_ID_JSON);
  }
  // Now verify public key signatures for technical correctness
  if (ALGORITHMS[findAlgorithm(decodedSignature.signatureAlgorithm) + 1]) {
    var publicKey;
    if (reader.hasProperty(PUBLIC_KEY_JSON)) {
      decodedSignature.publicKey = publicKey = reader.getPublicKey();
    } else {
      var arrayReader = reader.getArray(CERTIFICATE_PATH_JSON);
      if (!arrayReader.hasMore()) {
        throw new TypeError('Empty "certificatePath" not allowed');
      }
      decodedSignature.certificatePath = [];
      while (arrayReader.hasMore()) {
        decodedSignature.certificatePath.push(new Keys.Certificate(arrayReader.getBinary()));
      }
      var signatureCertificate = Keys.checkCertificatePath(decodedSignature.certificatePath)[0];
      publicKey = signatureCertificate.getPublicKey();
      if (reader.hasProperty(SIGNER_CERTIFICATE_JSON)) {
        var certPropReader = reader.getObject(SIGNER_CERTIFICATE_JSON);
        if (certPropReader.getString(ISSUER_JSON) != signatureCertificate.getIssuer() ||
            !certPropReader.getBigInteger(SERIAL_NUMBER_JSON).equals(signatureCertificate.getSerialNumber()) ||
            certPropReader.getString(SUBJECT_JSON) != signatureCertificate.getSubject()) {
          throw new TypeError('Non-matching certificate properties');
        }
      }
    }
    var hashAlgorithm = getHashAlgorithm(publicKey.jcs.type, decodedSignature.signatureAlgorithm);
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
  reader.checkForUnread();
  return decodedSignature;
};

exports.Signer = Signer;
exports.Verifier = Verifier;

exports.SIGNATURE_TYPE  = SIGNATURE_TYPE;

exports.PUBLIC_KEY_JSON = PUBLIC_KEY_JSON;
exports.SIGNATURE_JSON  = SIGNATURE_JSON;
exports.ALGORITHM_JSON  = ALGORITHM_JSON;
exports.VALUE_JSON      = VALUE_JSON;
