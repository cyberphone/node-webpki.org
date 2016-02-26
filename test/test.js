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

const fs = require('fs');
const crypto = require('crypto');

const Keys = require('..').Keys;
const Base64URL = require('..').Base64URL;
const JCS = require('..').JCS;

function readFile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const publicEcP256Key = Keys.decodePublicKeyFromPEM(readFile('public-p256.pem'));
const privateEcP256Pkcs1Key = Keys.decodePrivateKeyFromPEM(readFile('private-p256-pkcs1.pem'));
console.log(privateEcP256Pkcs1Key);
const ecCertificate = Keys.decodeCertificatePathFromPEM(readFile('certificate-p256.pem'));
const privateRsaPkcs8Key = Keys.decodePrivateKeyFromPEM(readFile('private-rsa-pkcs8.pem'));

console.log(JSON.stringify(new JCS.Signature(privateEcP256Pkcs1Key).sign({'statement':'Hello signed world!'})));
console.log(JSON.stringify(new JCS.Signature(privateRsaPkcs8Key,'RS512').sign({'statement':'Hello signed world!'})));

function base64run() {
  for (var times = 0; times < 20; times++) {
    for (var i = 0; i < 50; i++) {
      var iarr = new Uint8Array(i);
      for (var j = 0; j < i; j++) {
        iarr[j] =  Math.floor(Math.random()*256);
      }
      var b64 = Base64URL.encode(iarr);
//      console.log('Base64URL=' + b64);
      var arr = Base64URL.decode(b64);
      if (arr.length != iarr.length) throw 'Length error';
      for (var q = 0; q < arr.length; q++) {
        if (arr[q] != iarr[q]) throw 'Content error: ' + b64;
      }
    }
  }
  var shouldFail = true;
  try {
    var h = Base64URL.decode('a');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
  shouldFail = true;
  try {
    var h = Base64URL.decode('+xdFdYg');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
  shouldFail = true;
  try {
    var h = Base64URL.decode('/xdFdYg');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
}

function encodePublicKey(key, spkiBase64URL) {
  var spki = Base64URL.decode(spkiBase64URL);
  console.log();
  console.log(key.jcs);
  if (key.pem != '-----BEGIN PUBLIC KEY-----\n' +
                 new Buffer(spki).toString('base64') +
                 '\n-----END PUBLIC KEY-----\n') {
    throw new TypeError('Key mismatch: ' + spkiBase64URL);
  }
  Keys.decodePublicKeyFromPEM(key.pem);
}

base64run();

encodePublicKey(Keys.encodePublicKey({type: 'EC',
                                        curve: 'P-256',
x: 'GRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOU',
y: 'isxpqxSx6AAEmZfgL5HevS67ejfm_4HcsB883TUaccs'}),
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw');

encodePublicKey(Keys.encodePublicKey({type: 'EC',
                                        curve: 'P-521',
x: 'AQggHPZ-De2Tq_7U7v8ADpjyouKk6eV97Lujt9NdIcZgWI_cyOLv9HZulGWtC7I3X73ABE-rx95hAKbxiqQ1q0bA',
y: 'AP5yYckNtHGuzZ9Gb8oqueBXwgG5Riu5LnbhQUz5Mb_Xjo4mnhqe1f396ldZMUvyJdi2O03OZdhkpVv_ks2CsYHp'}),
'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCCAc9n4N7ZOr_tTu\
_wAOmPKi4qTp5X3su6O3010hxmBYj9zI4u_0dm6UZa0LsjdfvcAET6vH3mEApvGKpDWrRsAA_nJhyQ20ca7Nn0Zvyiq54FfCAblGK7kuduF\
BTPkxv9eOjiaeGp7V_f3qV1kxS_Il2LY7Tc5l2GSlW_-SzYKxgek');

encodePublicKey(Keys.encodePublicKey({type: 'RSA',
n: '6mct2A1crFheV3fiMvXzwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn\
8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3\
rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJTC_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3\
ltPOjDgADLKw', 
e: 'AQAB'}),
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mct2A1crFheV3fiMvX\
zwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4\
BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJT\
C_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3ltPOjDgADLKwIDAQAB');
