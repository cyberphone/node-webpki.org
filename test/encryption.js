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
/*                         Encryption                             */
/*================================================================*/

// NOT READY (RSA still missing)

const Assert = require('assert');
const Fs = require('fs');
const Crypto = require('crypto');

const Keys = require('..').Keys;
const ByteArray = require('..').ByteArray;
const Base64Url = require('..').Base64Url;
const JsonUtil = require('..').JsonUtil;
const Jef = require('..').Jef;

//ECDH test data

const ECDH_RESULT_WITH_KDF    = 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc';
const ECDH_RESULT_WITHOUT_KDF = 'SzFxLgluXyC07Pl5D9jMfIt-LIrZC9qByyJPYsDnuaY';

const JEF_TEST_STRING         = 'Hello encrypted world';
const JEF_SYM_KEY             = 'ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI';
const JEF_ECDH_OBJECT = {
  encryptedKey: {
    algorithm: "ECDH-ES",
    publicKey: {
      type: "EC",
      curve: "P-256",
      x: "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
      y: "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"
    },
    ephemeralKey: {
      type: "EC",
      curve: "P-256",
      x: "NjmaJp-6uRGPRLtaDOIWSF0exIF5Gy6JgngW6FQ6BGI",
      y: "f7mqQKvWu3_j9Zy9V-JE3_kv3oqYMw5zkkLuTMU6tdA"
    }
  },
  algorithm: "A128CBC-HS256",
  iv: "dTxUO-BoKpXIS6A5iS9fnw",
  tag: "PbYak7sTADNBAKeIwL8d2Q",
  cipherText: "8kMJ_Ju_V1NDO35wGH5eGqqrSoHHls_SyxFt4c0LTNA"
};

const JEF_SYM_OBJECT = {
  algorithm: "A128CBC-HS256",
  iv: "qlYEWzKR0o1pO-AZuI0ymQ",
  tag: "CHTPgPC-CE2fPPIUSHnjRg",
  cipherText: "1_HZs_Z0mvaBpRzDH5pkJFTt_ibz2ImeU6MmkNRoZJ8"
};

const ECHD_TEST_PRIVATE_KEY = 
'-----BEGIN PRIVATE KEY-----\
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgr/kHyZ+a06rmxM3yESK84r1otSg+\
aQcVStkRhA+iCM+gCgYIKoZIzj0DAQehRANCAARl7aWhJXfCuugpQ3/jOHAaEKqjdeG7W13hCN5D\
nAhVHR5S7XVwEWP3+eQN3580Gz3JuoYK9+DKfKfp7s0AhNGc\
-----END PRIVATE KEY-----';

const ECHD_TEST_PUBLIC_KEY = 
'-----BEGIN PUBLIC KEY-----\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkd\
YoDwFACwiYZ4BLjp/JbDkyFh8ZNPQiMGkXDZJLfgO/giuw==\
-----END PUBLIC KEY-----';

const test_private_key =
   Keys.createPrivateKeyFromPem(ECHD_TEST_PRIVATE_KEY);
const test_public_key =
   Keys.createPublicKeyFromPem(ECHD_TEST_PUBLIC_KEY);

// ECDH Static-Static
const ec1 = new Jef.Ecdh(test_private_key);
Assert.equal(Base64Url.encode(ec1.computeZ(test_public_key)), ECDH_RESULT_WITHOUT_KDF);

// ECDH Static-Static
const ec2 = new Jef.Ecdh(test_private_key);
Assert.equal(Base64Url.encode(ec2.computeWithKdf(test_public_key, 
                                                 Jef.JOSE_A128CBC_HS256_ALG_ID)),
             ECDH_RESULT_WITH_KDF);

// ECDH Ephemeral-Static
const ecStatic = new Jef.Ecdh(test_private_key);
const ecEphemeral = new Jef.Ecdh(test_private_key.getPublicKey());
Assert.deepEqual(ecStatic.computeZ(ecEphemeral.getPublicKey()),
                 ecEphemeral.computeZ(test_private_key.getPublicKey()));
                 
// ECDH Ephemeral-Ephemeral

function readPublicKey(path) {
  return Keys.createPrivateKeyFromPem(Fs.readFileSync(__dirname + '/' + path)).getPublicKey();
}

function ephemeralEphemeral(publicKey) {
  var one = new Jef.Ecdh(publicKey);
  var two = new Jef.Ecdh(publicKey);
  Assert.deepEqual(one.computeZ(two.getPublicKey()),
                   two.computeZ(one.getPublicKey()));
}
                   
ephemeralEphemeral(readPublicKey('private-ec-p521-key.pem'));
ephemeralEphemeral(readPublicKey('private-p256-pkcs1.pem'));
ephemeralEphemeral(readPublicKey('mybank-cert-and-key-p256.pem'));

Assert.equal(Base64Url.encode(Jef.receiverKeyAgreement(Jef.JOSE_ECDH_ES_ALG_ID,
                                                       Jef.JOSE_A128CBC_HS256_ALG_ID,
                                                       test_public_key,
                                                       test_private_key)),
             ECDH_RESULT_WITH_KDF);

var ecdhRes = Jef.senderKeyAgreement(Jef.JOSE_ECDH_ES_ALG_ID,
                                     Jef.JOSE_A128CBC_HS256_ALG_ID,
                                     test_private_key.getPublicKey());
Assert.deepEqual(ecdhRes.sharedSecret,
                 Jef.receiverKeyAgreement(Jef.JOSE_ECDH_ES_ALG_ID,
                                          Jef.JOSE_A128CBC_HS256_ALG_ID,
                                          ecdhRes.publicKey,
                                          test_private_key));

var encJson = new JsonUtil.ObjectWriter()
    .setEncryptionObject(ByteArray.stringToUtf8(JEF_TEST_STRING),
                         Jef.JOSE_A128CBC_HS256_ALG_ID,
                         test_private_key.getPublicKey(),
                         Jef.JOSE_ECDH_ES_ALG_ID);
console.log(encJson.toString());

Assert.equal(ByteArray.utf8ToString(new JsonUtil.ObjectReader(JSON.parse(encJson))
    .getEncryptedObject().getDecryptedData([test_private_key])),
             JEF_TEST_STRING);

Assert.equal(ByteArray.utf8ToString(new JsonUtil.ObjectReader(JEF_ECDH_OBJECT)
    .getEncryptedObject().getDecryptedData([test_private_key])),
            JEF_TEST_STRING);

var symRefKey = Base64Url.decode(JEF_SYM_KEY);
encJson = new JsonUtil.ObjectWriter()
    .setEncryptionObject(ByteArray.stringToUtf8(JEF_TEST_STRING),
                         Jef.JOSE_A128CBC_HS256_ALG_ID,
                         null,
                         symRefKey);
console.log(encJson.toString());
Assert.equal(ByteArray.utf8ToString(new JsonUtil.ObjectReader(JSON.parse(encJson))
    .getEncryptedObject().getDecryptedData(symRefKey)),
             JEF_TEST_STRING);

Assert.equal(ByteArray.utf8ToString(new JsonUtil.ObjectReader(JEF_SYM_OBJECT)
    .getEncryptedObject().getDecryptedData(symRefKey)),
             JEF_TEST_STRING);

var aesIv = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
var aesKey = new Uint8Array([8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,8]);
var aesData = new Uint8Array([5,4,3,2,1]);
var cipher = Crypto.createCipheriv('aes-128-cbc', aesKey, aesIv);
cipher.update(aesData);
var aesRes = cipher.final();
console.log('L=' + aesRes.length + ' D=' + Base64Url.encode(aesRes));
cipher = Crypto.createDecipheriv('aes-128-cbc', aesKey, aesIv);
cipher.update(aesRes);
Assert.deepEqual(new Uint8Array(cipher.final()), aesData);

function hex2Bin(hex) {
  return new Uint8Array(new Buffer(hex,'hex'));
}

const k = hex2Bin('000102030405060708090a0b0c0d0e0f' +
                  '101112131415161718191a1b1c1d1e1f');

const p = hex2Bin('41206369706865722073797374656d20' +
                  '6d757374206e6f742062652072657175' +
                  '6972656420746f206265207365637265' +
                  '742c20616e64206974206d7573742062' +
                  '652061626c6520746f2066616c6c2069' +
                  '6e746f207468652068616e6473206f66' +
                  '2074686520656e656d7920776974686f' +
                  '757420696e636f6e76656e69656e6365');

const iv = hex2Bin('1af38c2dc2b96ffdd86694092341bc04');

const a = hex2Bin('546865207365636f6e64207072696e63' +
                  '69706c65206f66204175677573746520' +
                  '4b6572636b686f666673');

const e = hex2Bin('c80edfa32ddf39d5ef00c0b468834279' +
                  'a2e46a1b8049f792f76bfe54b903a9c9' +
                  'a94ac9b47ad2655c5f10f9aef71427e2' +
                  'fc6f9b3f399a221489f16362c7032336' +
                  '09d45ac69864e3321cf82935ac4096c8' +
                  '6e133314c54019e8ca7980dfa4b9cf1b' +
                  '384c486f3a54c51078158ee5d79de59f' +
                  'bd34d848b3d69550a67646344427ade5' +
                  '4b8851ffb598f7f80074b9473c82e2db');

const t = hex2Bin('652c3fa36b0a7c5b3219fab3a30bc1c4');

var pout = Jef.contentDecryption(Jef.JOSE_A128CBC_HS256_ALG_ID,
                                 k,
                                 e,
                                 iv,
                                 a,
                                 t);
Assert.deepEqual(pout, p);

for (var q = 0; q < 100; q++) {
  var k1 = Jef.generateDataEncryptionKey(Jef.JOSE_A128CBC_HS256_ALG_ID);
  var enc = Jef.contentEncryption(Jef.JOSE_A128CBC_HS256_ALG_ID,
                                  k1,
                                  p,
                                  a);
  var dec = Jef.contentDecryption(Jef.JOSE_A128CBC_HS256_ALG_ID,
                                  k1,
                                  enc.cipherText,
                                  enc.iv,
                                  a,
                                  enc.tag);
   Assert.deepEqual(p,dec);
 }

