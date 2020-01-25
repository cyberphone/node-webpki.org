/*
 *  Copyright 2017-2020 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
/*                              Jsf                               */
/*================================================================*/

// Core classes for signing and verification of JSON signatures
// using the JSF (JSON Signature Format) scheme.

const Crypto = require('crypto');

const Keys      = require('./Keys');
const JsonUtil  = require('./JsonUtil');
const ByteArray = require('./ByteArray');
const Base64Url = require('./Base64Url');

    // Arguments
const EC_PUBLIC_KEY           = 'EC';
const RSA_PUBLIC_KEY          = 'RSA';
  
    // JSON properties
const ALGORITHM_JSON          = 'algorithm';
const EXTENSIONS_JSON         = 'extensions';
const KEY_ID_JSON             = 'keyId';
const PUBLIC_KEY_JSON         = 'publicKey';
const SIGNATURE_JSON          = 'signature';
const VALUE_JSON              = 'value';
const CERTIFICATE_PATH_JSON   = 'certificatePath';

const SIGNATURE_ALGORITHMS = [
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

function findSignatureAlgorithm(algorithmId) {
  for (var i = 0; i < SIGNATURE_ALGORITHMS.length; i += 3) {
    if (SIGNATURE_ALGORITHMS[i] == algorithmId) {
      return i;
    }
  }
  throw new TypeError('Unknown signatureAlgorithm: ' + algorithmId);
}

function isPublicKeySignature(algorithmId) {
  return SIGNATURE_ALGORITHMS[findSignatureAlgorithm(algorithmId) + 1] != null;
}

function getHashAlgorithm(keyType, signatureAlgorithm) {
  var algorithmIndex = findSignatureAlgorithm(signatureAlgorithm);
  if (keyType != SIGNATURE_ALGORITHMS[algorithmIndex + 1]) {
    throw new TypeError('Key "' + keyType + '" incompatible with algorithm "' + signatureAlgorithm + '"');
  }
  return SIGNATURE_ALGORITHMS[algorithmIndex + 2];
}

function checkForSignature(jcsObject, signatureLabel) {
  // JCS does not permit signing of top level [], only {}
  if (typeof jcsObject !== 'object' || Array.isArray(jcsObject)) {
    throw new TypeError('Top level element must be an "Object"');
  }
  return jcsObject[signatureLabel] !== undefined;
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
  this.outputPublicKeyData = true;
  if (signatureKey instanceof Keys.PrivateKey) {
    this.signatureKey = signatureKey;
    // Relying on defaults is generally bad, but the following values are JOSE compatible
    if (signatureAlgorithm === undefined) {
      signatureAlgorithm = signatureKey.jwk.kty == 'EC' ?
         Keys.getDefaultEcSignatureAlgorithm(signatureKey.jwk.crv) : 'RS256';
    }
    this.hashAlgorithm = getHashAlgorithm(signatureKey.jwk.kty, signatureAlgorithm);
    this._localSigner = this._asymmetricKeySign;
  } else {
    this.signatureKey = getHmacKey(signatureKey);
    if (signatureAlgorithm === undefined) {
      throw new TypeError('HMAC signatures must have a specified signature algorithm');
    }
    this.hashAlgorithm = getHashAlgorithm(null, signatureAlgorithm);
    this._localSigner = this._symmetricKeySign;
  }
  this.signatureAlgorithm = signatureAlgorithm;
  return this;
}

Signer.prototype.setSignatureLabel = function(signatureLabel) {
  this.signatureLabel = signatureLabel;
};

Signer.prototype._asymmetricKeySign = function(data2Sign) {
  var signer = Crypto.createSign(this.hashAlgorithm);
  signer.update(data2Sign);
  var signatureValue = signer.sign(this.signatureKey.pem);
  // There are (of course) two "standard" ways of representing ECDSA signatures... 
  if (this.signatureKey.jwk.kty == 'EC') {
    signatureValue = Keys.ecDer2JoseSignature(signatureValue, this.signatureKey.jwk.crv);
  }
  return signatureValue;
};

Signer.prototype._symmetricKeySign = function(data2Sign) {
  var signer = Crypto.createHmac(this.hashAlgorithm, this.signatureKey);
  signer.update(data2Sign);
  return signer.digest();
};

Signer.prototype.sign = function(object2Sign) {
  if (this.signatureLabel === undefined) {
    this.signatureLabel = SIGNATURE_JSON;
  }
  var signatureValue;
  if (checkForSignature(object2Sign, this.signatureLabel)) {
    throw new TypeError('Object is already signed');
  }
  if (this._used) {
    throw new TypeError('You can only call sign() once per instantiation');
  }
  this._used = true;
  var writer = new JsonUtil.ObjectWriter(object2Sign);
  var signatureWriter = writer.setObject(this.signatureLabel);
  signatureWriter.setString(ALGORITHM_JSON, this.signatureAlgorithm);
  if (this.keyId !== undefined) {
    signatureWriter.setString(KEY_ID_JSON, this.keyId);
  }
  if (this.outputPublicKeyData && this.signatureKey instanceof Keys.PrivateKey) {
    if (this.certificatePath === undefined) {
      signatureWriter.setPublicKey(this.signatureKey.getPublicKey());
    } else {
      var arrayWriter = signatureWriter.setArray(CERTIFICATE_PATH_JSON);
      this.certificatePath.forEach((certificate) => {
        arrayWriter.setBinary(certificate.getCertificateBlob());
      });
    }
  }
  signatureWriter.setBinary(VALUE_JSON, this._localSigner(writer.getCanonicalizedData()));
  return object2Sign;
};

Signer.prototype.setCertificatePath = function(certificatePath){
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

Signer.prototype.setOutputPublicKeyData = function(outputPublicKeyData){
  this.outputPublicKeyData = outputPublicKeyData;
  return this;
};

function DecodedSignature() {
  this.throwOnVerifyErrors = true;
  this.mustValidateSignature = true;
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

DecodedSignature.prototype._verify = function(result, message) {
  if (!result && this.throwOnVerifyErrors) {
    throw new TypeError(message); 
  }
  return result;
};

DecodedSignature.prototype.verifyPublicKey = function(publicKey) {
  return this._verify(this.getPublicKey().equals(publicKey),
                      'Public key does not match received key');
};

DecodedSignature.prototype.verifyTrust = function(trustList) {
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
  return this._verify(false, 'Certificate path is not trusted');
};

DecodedSignature.prototype.verifyHmac = function(hmacKey) {
  var verifier = Crypto.createHmac(getHashAlgorithm(null, this.signatureAlgorithm),
                                   getHmacKey(hmacKey));
  verifier.update(this.signedData);
  return this._verify(ByteArray.equals(verifier.digest(), this.signatureValue),
                      'Key does not match HMAC signature');
};

DecodedSignature.prototype.getSignatureType = function() {
  if (this.publicKey !== undefined) {
    return SIGNATURE_TYPE.PUBLIC_KEY;
  }
  if (this.certificatePath !== undefined) {
    return SIGNATURE_TYPE.PKI;
  }
  return isPublicKeySignature(this.signatureAlgorithm) ? SIGNATURE_TYPE.PUBLIC_KEY : SIGNATURE_TYPE.HMAC;
};

DecodedSignature.prototype._validatePublicKeySignature = function(publicKey) {
  var hashAlgorithm = getHashAlgorithm(publicKey.jwk.kty, this.signatureAlgorithm);
  // There are (of course) two "standard" ways of representing ECDSA signatures... 
  var signatureValue = this.signatureValue;
  if (publicKey.jwk.kty == 'EC') {
    signatureValue = Keys.ecJose2DerSignature(signatureValue, publicKey.jwk.crv);
  }
  var verifier = Crypto.createVerify(hashAlgorithm);
  verifier.update(this.signedData);
  if (!verifier.verify(publicKey.pem, signatureValue)) {
    throw new TypeError('Signature did not verify');
  }
  this.mustValidateSignature = false;
};

function Verifier(optionalSignatureLabel) {
  if (optionalSignatureLabel === undefined) {
    optionalSignatureLabel = SIGNATURE_JSON;
  }
  this.signatureLabel = optionalSignatureLabel;
  this.requirePublicKeyInfo = true;
}

Verifier.prototype.setThrowOnErrors = function(throwOnVerifyErrors) {
  this.throwOnVerifyErrors = throwOnVerifyErrors;
};

Verifier.prototype.setRequirePublicKeyInfo = function(requirePublicKeyInfo) {
  this.requirePublicKeyInfo = requirePublicKeyInfo;
};

Verifier.prototype.decodeSignature = function(signedObject) {
  var decodedSignature = new DecodedSignature();
  if (!checkForSignature(signedObject, this.signatureLabel)) {
    throw new TypeError('Object is not signed');
  }
  // We do not allow anything unknown within a signature object
  var reader = new JsonUtil.ObjectReader(signedObject, this.signatureLabel);
  // Clone "signature" child object
  var clone = Object.assign({}, signedObject[this.signatureLabel]);
  // Get signature value
  decodedSignature.signatureValue = reader.getBinary(VALUE_JSON);
  // Remove signature "value" property from the "signature" element
  delete signedObject[this.signatureLabel].value;
  // Get a "canonicalized" JSON string (=signed data).
  decodedSignature.signedData = JsonUtil.getCanonicalizedData(signedObject);
  // Restore signed object
  signedObject[this.signatureLabel] = clone;
  // We should always have an algorithm property
  decodedSignature.signatureAlgorithm = reader.getString(ALGORITHM_JSON);
  // An optional "keyId" should be catered for
  if (reader.hasProperty(KEY_ID_JSON)) {
    decodedSignature.keyId = reader.getString(KEY_ID_JSON);
  }
  // Now verify public key signatures for technical correctness
  if (isPublicKeySignature(decodedSignature.signatureAlgorithm)) {
    if (reader.hasProperty(PUBLIC_KEY_JSON)) {
      decodedSignature._validatePublicKeySignature(
         decodedSignature.publicKey = reader.getPublicKey());
    } else if (reader.hasProperty(CERTIFICATE_PATH_JSON)) {
      var arrayReader = reader.getArray(CERTIFICATE_PATH_JSON);
      if (!arrayReader.hasMore()) {
        throw new TypeError('Empty "certificatePath" not allowed');
      }
      decodedSignature.certificatePath = [];
      while (arrayReader.hasMore()) {
        decodedSignature.certificatePath.push(new Keys.Certificate(arrayReader.getBinary()));
      }
      var signatureCertificate = Keys.checkCertificatePath(decodedSignature.certificatePath)[0];
      decodedSignature._validatePublicKeySignature(signatureCertificate.getPublicKey());
    } else if (this.requirePublicKeyInfo) {
      throw new TypeError('Missing public key information');
    }
  }
  reader.checkForUnread();
  decodedSignature.throwOnVerifyErrors = this.throwOnVerifyErrors;
  return decodedSignature;
};

exports.Signer = Signer;
exports.Verifier = Verifier;

exports.SIGNATURE_TYPE  = SIGNATURE_TYPE;

exports.PUBLIC_KEY_JSON = PUBLIC_KEY_JSON;
exports.SIGNATURE_JSON  = SIGNATURE_JSON;
exports.ALGORITHM_JSON  = ALGORITHM_JSON;
exports.VALUE_JSON      = VALUE_JSON;
exports.KEY_ID_JSON     = KEY_ID_JSON;
