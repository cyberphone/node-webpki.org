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
/*                           EncryptedData                        */
/*================================================================*/

// Class for performing JSON-encoded:
// - Static-ephemeral ECDH operations
// - Symmetric-key encryption/decryption operations

////////////////////////////////////////////////////////////////////////////////
// This is effectively a "remake" of a subset of JWE.  Why a remake?          //
// Because the encryption system (naturally) borrows heavily from JCS         //
// including public key structures and property naming conventions.           //
//                                                                            //
// The supported algorithms are though JOSE compatible including their names. //
////////////////////////////////////////////////////////////////////////////////

const Jcs = require('./Jcs');
const ByteArray = require('./ByteArray');
const Encryption = require('./Encryption');
const JsonUtil = require('./JsonUtil');

const ENCRYPTED_DATA_JSON  = 'encryptedData';
const ENCRYPTED_KEY_JSON   = 'encryptedKey';
const STATIC_KEY_JSON      = 'staticKey';
const EPHEMERAL_KEY_JSON   = 'ephemeralKey';
const IV_JSON              = 'iv';
const TAG_JSON             = 'tag';
const CIPHER_TEXT_JSON     = 'cipherText';

function isRsaKey(keyEncryptionAlgorithm) {
  return keyEncryptionAlgorithm.indexOf('RSA') >= 0;
}

function compatible(privateKey, keyEncryptionAlgorithm) {
  return true;
}

function EncryptedData(reader) {
  var rd = reader.getObject(ENCRYPTED_DATA_JSON);
  this.dataEncryptionAlgorithm = rd.getString(Jcs.ALGORITHM_JSON);
  this.iv = rd.getBinary(IV_JSON);
  this.tag = rd.getBinary(TAG_JSON);
  this.encryptedKey = rd.getObject(ENCRYPTED_KEY_JSON);
  this.authenticatedData = this.encryptedKey.getNormalizedData();
  this.keyEncryptionAlgorithm = this.encryptedKey.getString(Jcs.ALGORITHM_JSON);
  if (isRsaKey(this.keyEncryptionAlgorithm)) {
    this.publicKey = this.encryptedKey.getPublicKey();
    this.encryptedKeyData = encryptedKey.getBinary(CIPHER_TEXT_JSON);
  } else {
    this.publicKey = this.encryptedKey.getObject(STATIC_KEY_JSON).getPublicKey();
    this.ephemeralPublicKey = this.encryptedKey.getObject(EPHEMERAL_KEY_JSON).getPublicKey();
  }
  this.encryptedData = rd.getBinary(CIPHER_TEXT_JSON);
}

EncryptedData.prototype.getDecryptedData = function(decryptionKeys) {
  var notFound = true;
  for (var q = 0; q < decryptionKeys.length; q++) {
    var decryptionKey = decryptionKeys[q];
    if (decryptionKey.getPublicKey().equals(this.publicKey)) {
      notFound = false;
      if (compatible(decryptionKey, this.keyEncryptionAlgorithm)) {
        return new JsonUtil.ObjectReader(JSON.parse(ByteArray.utf8ToString(
          Encryption.contentDecryption(this.dataEncryptionAlgorithm,
                         isRsaKey(this.keyEncryptionAlgorithm) ?
               Encryption.rsaDecryptKey(this.keyEncryptionAlgorithm,
                                        this.encryptedKeyData,
                                        decryptionKey)
                         :
               Encryption.receiverKeyAgreement(this.keyEncryptionAlgorithm,
                                               this.dataEncryptionAlgorithm,
                                               this.ephemeralPublicKey,
                                               decryptionKey),
                                       this.encryptedData,
                                       this.iv,
                                       this.authenticatedData,
                                       this.tag))));
      }
    }
  }
  throw new TypeError(notFound ? 'No matching key found' : 'No matching key+algorithm found');
};

EncryptedData.encode = function(unencryptedData,
                                dataEncryptionAlgorithm,
                                publicKeyEncryptionKey,
                                keyEncryptionAlgorithm) {
  var encryptionObject = new JsonUtil.ObjectWriter();
  var encryptedData = encryptionObject.setObject(ENCRYPTED_DATA_JSON);
  var encryptedKey = encryptedData.setObject(ENCRYPTED_KEY_JSON)
    .setString(Jcs.ALGORITHM_JSON, keyEncryptionAlgorithm);
  var dataEncryptionKey;
  if (isRsaKey(keyEncryptionAlgorithm)) {
    encryptedKey.setPublicKey(publicKeyEncryptionKey);
    dataEncryptionKey = Encryption.generateDataEncryptionKey(dataEncryptionAlgorithm);
    encryptedKey.setBinary(CIPHER_TEXT_JSON,
    Encryption.rsaEncryptKey(keyEncryptionAlgorithm,
                             dataEncryptionKey,
                             publicKeyEncryptionKey));
  } else {
    var ecdhRes = Encryption.senderKeyAgreement(keyEncryptionAlgorithm,
                                                dataEncryptionAlgorithm,
                                                publicKeyEncryptionKey);
    dataEncryptionKey = ecdhRes.sharedSecret;
    encryptedKey.setObject(STATIC_KEY_JSON)
      .setPublicKey(publicKeyEncryptionKey);
    encryptedKey.setObject(EPHEMERAL_KEY_JSON)
      .setPublicKey(ecdhRes.publicKey);
  }
  var result = Encryption.contentEncryption(dataEncryptionAlgorithm,
                                            dataEncryptionKey,
                                            unencryptedData.getNormalizedData(),
                                            encryptedKey.getNormalizedData());
  encryptedData
    .setString(Jcs.ALGORITHM_JSON, dataEncryptionAlgorithm)
    .setBinary(IV_JSON, result.iv)
    .setBinary(TAG_JSON, result.tag)
    .setBinary(CIPHER_TEXT_JSON, result.cipherText);
  return encryptionObject;
};

module.exports = EncryptedData;
