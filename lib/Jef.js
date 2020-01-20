/*
 *  Copyright 2006-2017 WebPKI.org (http://webpki.org).
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

////////////////////////////////////////////////////////////////////////////////
// JEF is effectively a "remake" of a subset of JWE.  Why a remake?           //
// Because the encryption system (naturally) borrows heavily from JSF         //
// including public key structures and property naming conventions.           //
//                                                                            //
// The supported algorithms are though JOSE compatible including their names. //
////////////////////////////////////////////////////////////////////////////////

const Crypto = require('crypto');

const Keys      = require('./Keys');
const ByteArray = require('./ByteArray');
const Base64Url = require('./Base64Url');
const Random    = require('./Random');
const Jsf       = require('./Jsf');
const JsonUtil  = require('./JsonUtil');

const KEY_ENCRYPTION_JSON       = 'keyEncryption';
const ENCRYPTED_KEY_JSON        = 'encryptedKey';
const EPHEMERAL_KEY_JSON        = 'ephemeralKey';
const IV_JSON                   = 'iv';
const TAG_JSON                  = 'tag';
const CIPHER_TEXT_JSON          = 'cipherText';

const JOSE_A128CBC_HS256_ALG_ID = 'A128CBC-HS256';
const JOSE_RSA_OAEP_256_ALG_ID  = 'RSA-OAEP-256';  
const JOSE_ECDH_ES_ALG_ID       = 'ECDH-ES';

function checkDataEncryptionAlgorithm(dataEncryptionAlgorithm) {
  if (dataEncryptionAlgorithm === undefined) {
    throw new TypeError('Missing "dataEncryptionAlgorithm"');
  }
  if (dataEncryptionAlgorithm != JOSE_A128CBC_HS256_ALG_ID) {
    throw new TypeError('Unsupported "dataEncryptionAlgorithm"');
  }
}

function checkEcKeyEncryptionAlgorithm(keyEncryptionAlgorithm) {
  if (keyEncryptionAlgorithm === undefined) {
    throw new TypeError('Missing "keyEncryptionAlgorithm"');
  }
  if (keyEncryptionAlgorithm != JOSE_ECDH_ES_ALG_ID) {
    throw new TypeError('Unsupported "keyEncryptionAlgorithm"');
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
  checkDataEncryptionAlgorithm(dataEncryptionAlgorithm);
  var iv = Random.generateRandomNumber(16);
  var cipher = Crypto.createCipheriv('AES-128-CBC', key.subarray(16), iv);
  var partial = new Uint8Array(cipher.update(plainText));
  var cipherText = ByteArray.add(partial, new Uint8Array(cipher.final()));
  return { cipherText: cipherText, iv: iv, tag: getTag(key, cipherText, iv, authenticatedData) };
}

function generateDataEncryptionKey(dataEncryptionAlgorithm) {
  checkDataEncryptionAlgorithm(dataEncryptionAlgorithm);
  return Random.generateRandomNumber(32);
}

function contentDecryption(dataEncryptionAlgorithm,
                           key,
                           cipherText,
                           iv,
                           authenticatedData,
                           tag) {
  checkDataEncryptionAlgorithm(dataEncryptionAlgorithm);
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
  if (key.jwk.kty != 'EC') {
    throw new TypeError('Not "EC" key');
  }
  for (var i = 0; i < CURVE_TO_INTERNAL_ALGORITHM_ID.length; i += 2) {
    if (key.jwk.crv == CURVE_TO_INTERNAL_ALGORITHM_ID[i]) {
      return CURVE_TO_INTERNAL_ALGORITHM_ID[i + 1];
    }
  }
  throw new TypeError('No algorithm for curve: ' + key.jwk.crv);
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
    var jwk = Object.assign({}, key.jwk);
    jwk.x = Base64Url.encode(publicKeyBlob.subarray(1, 1 + coordinateLength)),
    jwk.y = Base64Url.encode(publicKeyBlob.subarray(1 + coordinateLength));
    this.publicKey = Keys.encodePublicKey(jwk);
  } else {
    throw new TypeError('Argument must be "PrivateKey" or "PublicKey"');
  }
  this.crv = key.jwk.crv;
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
    if (this.crv != publicKey.jwk.crv) {
      throw new TypeError('"PublicKey" curve does not match Ecdh curve')
    }
    return new Uint8Array(this.ecdh.computeSecret(publicKey.ecPublicKeyBlob));
  }
  throw new TypeError('Argument must be a "PublicKey"');
};

Ecdh.prototype.computeWithKdf = function(publicKey, dataEncryptionAlgorithm) {
  checkDataEncryptionAlgorithm(dataEncryptionAlgorithm);
  var Z = this.computeZ(publicKey);
  var hash = Crypto.createHash('SHA256');
  // Round 1 indicator
  hash.update(new Uint8Array([0,0,0,1]));
  // Z
  hash.update(Z);
  // AlgorithmID = Content encryption algorithm
  hash.update(new Uint8Array([0,0,0,dataEncryptionAlgorithm.length]));
  hash.update(ByteArray.stringToUtf8(dataEncryptionAlgorithm));
  // PartyUInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // PartyVInfo = Empty
  hash.update(new Uint8Array([0,0,0,0]));
  // SuppPubInfo = Key length in bits
  hash.update(new Uint8Array([0,0,1,0]));
  return new Uint8Array(hash.digest());
};

function receiverKeyAgreement(keyEncryptionAlgorithm,
                              dataEncryptionAlgorithm,
                              receivedPublicKey,
                              privateKey) {
  checkEcKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
  var ecdh = new Ecdh(privateKey);
  return ecdh.computeWithKdf(receivedPublicKey, dataEncryptionAlgorithm) 
}

function senderKeyAgreement(keyEncryptionAlgorithm,
                            dataEncryptionAlgorithm,
                            publicStaticKey) {
  checkEcKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
  var ecdh = new Ecdh(publicStaticKey);
  var ecdhRes = {};
  ecdhRes.sharedSecret = ecdh.computeWithKdf(publicStaticKey, dataEncryptionAlgorithm);
  ecdhRes.publicKey = ecdh.getPublicKey();
  return ecdhRes;
}

function isRsaAlgorithm(keyEncryptionAlgorithm) {
  return keyEncryptionAlgorithm.indexOf('RSA') >= 0;
}

function compatible(privateKey, keyEncryptionAlgorithm) {
  return true;
}

function EncryptedData(reader) {
  // Clone encryption object
  var clone = Object.assign({}, reader.object);
  // Remove properties
  delete clone[IV_JSON];
  delete clone[TAG_JSON];
  delete clone[CIPHER_TEXT_JSON];
  // Get a "normalized" rather than "canonicalized" JSON string (=signed data).
  this.authenticatedData = JsonUtil.getNormalizedData(clone);
  // Now read the actual object
  this.dataEncryptionAlgorithm = reader.getString(Jsf.ALGORITHM_JSON);
  this.iv = reader.getBinary(IV_JSON);
  this.tag = reader.getBinary(TAG_JSON);
  this.symmmetricKeyEncryption = true;
  if (reader.hasProperty(KEY_ENCRYPTION_JSON)) {
    this.symmmetricKeyEncryption = false;
    var keyEncryption = reader.getObject(KEY_ENCRYPTION_JSON);
    this.keyEncryptionAlgorithm = keyEncryption.getString(Jsf.ALGORITHM_JSON);
    if (keyEncryption.hasProperty(Jsf.PUBLIC_KEY_JSON)) {
      this.publicKey = keyEncryption.getPublicKey();
    } else {
      this.keyId = keyEncryption.getStringConditional(Jsf.KEY_ID_JSON);
    }
    if (isRsaAlgorithm(this.keyEncryptionAlgorithm)) {
      this.encryptedKeyData = keyEncryption.getBinary(ENCRYPTED_KEY_JSON);
    } else {
      this.ephemeralKey = keyEncryption.getObject(EPHEMERAL_KEY_JSON).getCorePublicKey();
    }
  } else {
    this.keyId = reader.getStringConditional(Jsf.KEY_ID_JSON);
  }
  this.encryptedData = reader.getBinary(CIPHER_TEXT_JSON);
  reader.checkForUnread();
}

EncryptedData.prototype.getDecryptedData = function(decryptionKeys) {
  if (this.symmmetricKeyEncryption) {
    return contentDecryption(this.dataEncryptionAlgorithm,
                             decryptionKeys,
                             this.encryptedData,
                             this.iv,
                             this.authenticatedData,
                             this.tag);
  }
  var notFound = true;
  for (var q = 0; q < decryptionKeys.length; q++) {
    var decryptionKey = decryptionKeys[q];
    var keyId = decryptionKey.getKeyId();
    if ((keyId && keyId == this.keyId) || decryptionKey.getPublicKey().equals(this.publicKey)) {
      notFound = false;
      if (compatible(decryptionKey, this.keyEncryptionAlgorithm)) {
        return contentDecryption(this.dataEncryptionAlgorithm,
                            isRsaAlgorithm(this.keyEncryptionAlgorithm) ?
              rsaDecryptKey(this.keyEncryptionAlgorithm,
                            this.encryptedKeyData,
                            decryptionKey)
                        :
              receiverKeyAgreement(this.keyEncryptionAlgorithm,
                                   this.dataEncryptionAlgorithm,
                                   this.ephemeralKey,
                                   decryptionKey),
                                 this.encryptedData,
                                 this.iv,
                                 this.authenticatedData,
                                 this.tag);
      }
    }
  }
  throw new TypeError(notFound ? 'No matching key found' : 'No matching key+algorithm found');
};

EncryptedData.prototype.require = function(publicKeyEncryption) {
  if (this.symmmetricKeyEncryption == publicKeyEncryption) {
    throw new TypeError('Wrong type of encryption');
  }
  return this;
};

exports.Ecdh = Ecdh;

exports.contentEncryption         = contentEncryption;
exports.contentDecryption         = contentDecryption;
exports.generateDataEncryptionKey = generateDataEncryptionKey;
exports.receiverKeyAgreement      = receiverKeyAgreement;
exports.senderKeyAgreement        = senderKeyAgreement;
exports.isRsaAlgorithm            = isRsaAlgorithm;

exports.EncryptedData             = EncryptedData;

exports.JOSE_A128CBC_HS256_ALG_ID = JOSE_A128CBC_HS256_ALG_ID;
exports.JOSE_RSA_OAEP_256_ALG_ID  = JOSE_RSA_OAEP_256_ALG_ID;  
exports.JOSE_ECDH_ES_ALG_ID       = JOSE_ECDH_ES_ALG_ID;

exports.KEY_ENCRYPTION_JSON       = KEY_ENCRYPTION_JSON;
exports.ENCRYPTED_KEY_JSON        = ENCRYPTED_KEY_JSON;
exports.EPHEMERAL_KEY_JSON        = EPHEMERAL_KEY_JSON;
exports.IV_JSON                   = IV_JSON;
exports.TAG_JSON                  = TAG_JSON;
exports.CIPHER_TEXT_JSON          = CIPHER_TEXT_JSON;
