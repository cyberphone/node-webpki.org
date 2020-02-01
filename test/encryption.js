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
/*                         Encryption                             */
/*================================================================*/

// NOT READY (RSA still missing)

const Assert = require('assert');
const Fs     = require('fs');
const Crypto = require('crypto');

const Keys      = require('..').Keys;
const ByteArray = require('..').ByteArray;
const Base64Url = require('..').Base64Url;
const JsonUtil  = require('..').JsonUtil;
const Jef       = require('..').Jef;

// JEF test data

const ECDH_RESULT_WITH_KDF    = 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc';
const ECDH_RESULT_WITHOUT_KDF = 'SzFxLgluXyC07Pl5D9jMfIt-LIrZC9qByyJPYsDnuaY';

const JEF_TEST_STRING         = ByteArray.stringToUtf8('Hello encrypted world!');
const JEF_SYM_KEY             = 'ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI';
const JEF_EC_KEY_ID           = '20170101:mybank:ec';
const JEF_RSA_KEY_ID          = '20170101:mybank:rsa';

const JEF_SYM_OBJECT = {
  algorithm: "A128CBC-HS256",
  iv: "3FKQ15sb0iffjlzayFsSPA",
  tag: "3wIUITJQ0sLk7GuNDRCX_g",
  cipherText: "VLUNNBJdwhK-Sd9RPbmZS52e-AZIcThHlELm_IQ8uCY"
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

const RSA_TEST_PRIVATE_KEY = 
'-----BEGIN PRIVATE KEY-----\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDL//I5ddqKwqoJbZQJw7GllEII\
h3PTjTvgqudBcw6NK6WdoH6QFRRXj0ZzyMEjWTsg/SAt20g+O/ZZUVp7C3dubY/a3KZFg3Dq2uKy\
hW1KzBaE8M1HXZkSFQ2Hi8jImzJixlGDbLXX+CGYrk95FHFKpXB2Br4c66FeE38rIP4IvtXEdDCl\
4CbBZcO8/B5OktbOVWhHM5KQJuyW7MJb1KHSsEc97ikFJxpjahdCyJa3yebenquB8EAuw//ykR23\
lb50cyKFNh+y4s2uglGeChye8+G/jgXU4Np9TB+4s974ukbzMjMwYedoPgYQI5q2vM6o+NQKfKId\
yE0VqnUdTySFAgMBAAECggEBAJYnB7U/h+JGsj1KSIJ/ZgyH+aqpeJmoBQCzCpBkDbve+oHxFfcb\
bOOd869Zfr9z+E+pwLvAAYa9P/AyLzUOFZRUVGQ1sLTNsJlNDztzdiRt381uKMp0nCxxDopMWzc8\
9HM7odfodlhGrQPimWB3qYPWDdbx05EZ5qaGFz45hIIOFAQj2VgWKokjmE5ZsjIdziax5YZGqjEG\
SA9WnFNVj3+a7ZffrNwy2I2lfbIJPuHZZlEoVqGuK7itbS+IWVe+7YB8xtA+I5p43O2h5x9tGghq\
Bs9EpCAx+WPlM6LRvryr1Vv/S2l0qxHH7qrNmLWl3osQdV6fxCN8p7bdc/rzwukCgYEA8VLnM8VF\
1pW1M31jQfec0h4NUO3WuLTR8xJJA1Qn572zYC1jd5myLOYIdZ1KpSDeTtydEiR63OMeht4Ph5Gg\
Bd8d8Mfq5ANpyhmMO8eqegzx51AuKFRrRyLVtjgwdt3Y+xzsagR1ovHg7C0nvMoBGBC6R4HqRmX7\
Yeq/Me4Kb2MCgYEA2Gf00+LjLNyHjcPZGA4mEQ/Zo+5cj9t6X2+m8Vyu40Id1OOdzhbE1jifls0p\
iTdD2/dxGcYLhtDxJtvRr58YsArJSKOdDAZxETfh4f3K/QEoWiVFKd2Ig2P67k4D1sEPoFjM8ri3\
vFstAawQv06nwgKtNWhfkOishKjpfEPJZPcCgYEAoykgNLqOa3Uw3C1MrM9TciTrb+o+oQdwY93b\
C6sch+yUmNRXSgfalcy5r3u3eknsxHkYoamUgD/25czBxzFIdm/R+HfScnN0VTZMwCZRNtAFxhVJ\
/+6D0cbVo6v96IA6Mh3uIgf92TucjVJCabxSXQkCSVKnKQ3Olvd2abW9zG0CgYBS/ltov4T8eX8L\
IWcq0JJMzNVdB1c8XKHr4/gUbMUtpvel471rglPvDDw4K2qYkzdVLuqTRd65z3wMuRUL02o2aYyU\
bRsXt4i5X8MjVp/4s+7z04NY8Psf2MItjoHuZJBHoIbJN4pPlHAISiMKG3I+96PR7bto6bLwFY+l\
9qFQNQKBgQCTJYJQUfyYLh69dE/R+UBNh2sA8hbC4s733jlDkVdFPjWMVbMBjw076nM9Yh+jy45Z\
uADEbzdHMqUOo3IN9Tcs8ihi4ELywbAaFTXYTgDQvsigtaLojd5dqyJfWx3eeCNG4cOIFYPkMd1D\
JJ+xMkjm/RNvgq6inQoO9/3A12WvrQ==\
-----END PRIVATE KEY-----';


const test_private_key =  Keys.createPrivateKeyFromPem(ECHD_TEST_PRIVATE_KEY);
const test_public_key = Keys.createPublicKeyFromPem(ECHD_TEST_PUBLIC_KEY);
const test_private_rsa_key = Keys.createPrivateKeyFromPem(RSA_TEST_PRIVATE_KEY);

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
                   
ephemeralEphemeral(readPublicKey('p256privatekey.pem'));
ephemeralEphemeral(readPublicKey('p521privatekey.pem'));
ephemeralEphemeral(readPublicKey('p384privatekey.pem'));

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
test_private_key.setKeyId(JEF_EC_KEY_ID);
var keySet = [test_private_rsa_key,test_private_key];

var encJson =
   JsonUtil.ObjectWriter.setAsymEncryptionObject(JEF_TEST_STRING,
                                                 Jef.JOSE_A128CBC_HS256_ALG_ID,
                                                 test_private_key.getPublicKey(),
                                                 null,
                                                 Jef.JOSE_ECDH_ES_ALG_ID).toString();
console.log(encJson);
Assert.deepEqual(JsonUtil.ObjectReader.parse(encJson)
                     .getEncryptionObject().getDecryptedData(keySet),
                 JEF_TEST_STRING);

var encJson =
  JsonUtil.ObjectWriter.setAsymEncryptionObject(JEF_TEST_STRING,
                                                Jef.JOSE_A128CBC_HS256_ALG_ID,
                                                test_private_key.getPublicKey(),
                                                JEF_EC_KEY_ID,
                                                Jef.JOSE_ECDH_ES_ALG_ID).toString();
console.log(encJson);
Assert.deepEqual(JsonUtil.ObjectReader.parse(encJson)
                    .getEncryptionObject().getDecryptedData(keySet),
                JEF_TEST_STRING);

/*
Assert.deepEqual(new JsonUtil.ObjectReader(JEF_ECDH_OBJECT_1)
                     .getEncryptionObject().getDecryptedData(keySet),
                JEF_TEST_STRING);

Assert.deepEqual(new JsonUtil.ObjectReader(JEF_ECDH_OBJECT_2)
                     .getEncryptionObject().getDecryptedData(keySet),
                 JEF_TEST_STRING);

*/
var symRefKey = Base64Url.decode(JEF_SYM_KEY);
encJson =
    JsonUtil.ObjectWriter.setSymEncryptionObject(JEF_TEST_STRING,
                                                 Jef.JOSE_A128CBC_HS256_ALG_ID,
                                                 null,
                                                 symRefKey).toString();
console.log(encJson);
Assert.deepEqual(JsonUtil.ObjectReader.parse(encJson)
                     .getEncryptionObject().getDecryptedData(symRefKey),
                 JEF_TEST_STRING);

Assert.deepEqual(new JsonUtil.ObjectReader(JEF_SYM_OBJECT)
                     .getEncryptionObject().getDecryptedData(symRefKey),
                 JEF_TEST_STRING);

encJson =
    JsonUtil.ObjectWriter.setSymEncryptionObject(JEF_TEST_STRING,
                                                 Jef.JOSE_A128CBC_HS256_ALG_ID,
                                                 "myKey",
                                                 symRefKey).toString();
console.log(encJson);
Assert.deepEqual(JsonUtil.ObjectReader.parse(encJson)
                     .getEncryptionObject().getDecryptedData(symRefKey),
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
  return new Uint8Array(Buffer.from(hex,'hex'));
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

