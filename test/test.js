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
/*                            Test                                */
/*================================================================*/

// Unit testing suite

const Fs        = require('fs');
const assert    = require('assert');

const Keys      = require('..').Keys;
const Base64Url = require('..').Base64Url;
const Jsf       = require('..').Jsf;
const CertRead  = require('./certread');
const Hash      = require('..').Hash;
const Random    = require('..').Random;
const Logging   = require('..').Logging;

var logger = new Logging.Logger(__filename);
logger.info('Starting');

function readFile(path) {
  return Fs.readFileSync(__dirname + '/' + path).toString();
}

function readJSON(path) {
  return JSON.parse(readFile(path));
}

const publicEcP256Key = Keys.createPublicKeyFromPem(readFile('public-p256.pem'));
const privateEcP256Pkcs1Key = Keys.createPrivateKeyFromPem(readFile('private-p256-pkcs8.pem'));
const ecCertificatePath = Keys.createCertificatesFromPem(readFile('certificate-p256.pem'));
const privateRsaPkcs8Key = Keys.createPrivateKeyFromPem(readFile('private-rsa-pkcs8.pem'));

function signStuff(privateKey, algorithm) {
  var res = new Jsf.Signer(privateKey, algorithm).sign({'statement':'Hello signed world!'});
  var result = new Jsf.Verifier().decodeSignature(res);
  if (result.getSignatureType() != Jsf.SIGNATURE_TYPE.PUBLIC_KEY) {
    throw new TypeError('Wrong signature type');
  }
}

signStuff(privateEcP256Pkcs1Key);
signStuff(privateEcP256Pkcs1Key, 'ES512');
signStuff(privateRsaPkcs8Key);

for (var q = 0; q < 1000; q++) {
  new Jsf.Verifier().decodeSignature(new Jsf.Signer(privateEcP256Pkcs1Key).sign({'statement':'Hello signed world!'}));
}

var certSigner = new Jsf.Signer(privateEcP256Pkcs1Key)
  .setCertificatePath(ecCertificatePath);
var certRes = certSigner.sign({'statement':'Hello signed world!'});
console.log(JSON.stringify(certRes));
if (new Jsf.Verifier().decodeSignature(certRes).getSignatureType() != Jsf.SIGNATURE_TYPE.PKI) {
  throw new TypeError('Expected PKI');
}

["p256#es256","p384#es384", "p521#es512","r2048#rs256"].forEach((element) => {
  var jsObject = readJSON(element + '@jwk.json');
  var decodedSignature = new Jsf.Verifier().decodeSignature(jsObject);
  if (decodedSignature.getSignatureType() != Jsf.SIGNATURE_TYPE.PUBLIC_KEY) {
    throw new TypeError('Expected PUBLIC_KEY');
  }
  console.log(element);
  var privateKey = Keys.createPrivateKeyFromPem(readFile(element.substring(0, element.length -6) + 'privatekey.pem'));
  decodedSignature.verifyPublicKey(privateKey.getPublicKey());
  var signer = new Jsf.Signer(privateKey);
  jsObject = signer.sign({'statement':'Hello signed world!'});
  decodedSignature = new Jsf.Verifier().decodeSignature(jsObject);
  if (decodedSignature.getSignatureType() != Jsf.SIGNATURE_TYPE.PUBLIC_KEY) {
    throw new TypeError('Expected PKI');
  }
  decodedSignature.verifyPublicKey(privateKey.getPublicKey());
  signer = new Jsf.Signer(privateKey);
  signer.setSignatureLabel("attestation");
  jsObject = signer.sign({'statement':'Hello signed world!'});
  decodedSignature = new Jsf.Verifier("attestation").decodeSignature(jsObject);
});

// CertRead.scanCerts();

function base64run() {
  for (var times = 0; times < 20; times++) {
    for (var i = 0; i < 50; i++) {
      var iarr = new Uint8Array(i);
      for (var j = 0; j < i; j++) {
        iarr[j] =  Math.floor(Math.random()*256);
      }
      var b64 = Base64Url.encode(iarr);
//      console.log('Base64Url=' + b64);
      var arr = Base64Url.decode(b64);
      if (arr.length != iarr.length) throw 'Length error';
      for (var q = 0; q < arr.length; q++) {
        if (arr[q] != iarr[q]) throw 'Content error: ' + b64;
      }
    }
  }
  var shouldFail = true;
  try {
    var h = Base64Url.decode('a');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
  shouldFail = true;
  try {
    var h = Base64Url.decode('+xdFdYg');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
  shouldFail = true;
  try {
    var h = Base64Url.decode('/xdFdYg');
  } catch (e) {
    shouldFail = false;
  }
  if (shouldFail) {
    throw 'Bad';
  }
}

function encodePublicKey(key, spkiBase64URL) {
  var spki = Base64Url.decode(spkiBase64URL);
  if (key.pem != '-----BEGIN PUBLIC KEY-----\n' +
                 Buffer.from(spki).toString('base64') +
                 '\n-----END PUBLIC KEY-----\n') {
    throw new TypeError('Key mismatch: ' + spkiBase64URL);
  }
  Keys.createPublicKeyFromPem(key.pem);
}

base64run();

encodePublicKey(Keys.encodePublicKey({kty: 'EC',
crv: 'P-256',
x: 'GRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOU',
y: 'isxpqxSx6AAEmZfgL5HevS67ejfm_4HcsB883TUaccs'}),
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw');

encodePublicKey(Keys.encodePublicKey({kty: 'EC',
crv: 'P-521',
x: 'AQggHPZ-De2Tq_7U7v8ADpjyouKk6eV97Lujt9NdIcZgWI_cyOLv9HZulGWtC7I3X73ABE-rx95hAKbxiqQ1q0bA',
y: 'AP5yYckNtHGuzZ9Gb8oqueBXwgG5Riu5LnbhQUz5Mb_Xjo4mnhqe1f396ldZMUvyJdi2O03OZdhkpVv_ks2CsYHp'}),
'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCCAc9n4N7ZOr_tTu\
_wAOmPKi4qTp5X3su6O3010hxmBYj9zI4u_0dm6UZa0LsjdfvcAET6vH3mEApvGKpDWrRsAA_nJhyQ20ca7Nn0Zvyiq54FfCAblGK7kuduF\
BTPkxv9eOjiaeGp7V_f3qV1kxS_Il2LY7Tc5l2GSlW_-SzYKxgek');

encodePublicKey(Keys.encodePublicKey({kty: 'RSA',
n: '6mct2A1crFheV3fiMvXzwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn\
8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3\
rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJTC_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3\
ltPOjDgADLKw', 
e: 'AQAB'}),
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mct2A1crFheV3fiMvX\
zwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4\
BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJT\
C_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3ltPOjDgADLKwIDAQAB');

var secretKey = Buffer.from('F4C74F3398C49CF46D93EC9818832661A40BAE4D204D75503614102074346909', 'hex');
var hmac = new Jsf.Signer(secretKey, 'HS256').setKeyId('mykey').sign({'k':6});
console.log(JSON.stringify(hmac));
var hmacDecoder = new Jsf.Verifier().decodeSignature(hmac);
if (hmacDecoder.getSignatureType() != Jsf.SIGNATURE_TYPE.HMAC) {
  throw new TypeError('Wrong kind of signature');
}
console.log('hmac=' + hmacDecoder.verifyHmac(secretKey));

function hashJsonObject(hashAlgorithm, expectedResult) {
  assert.equal(Base64Url.encode(Hash.hashObject(hashAlgorithm, 
                                                { property: 'Text \u0000 \n \u20ac \u00d6' })),
               expectedResult);
}

hashJsonObject('SHA256', 'P3IwEoCLP4Su7ImnobuIybAcDvpUxPSXY0GgCQPWAms');
hashJsonObject('SHA384', '5pPdhqLxgNq6BotieCcc5I3GjwpYuIX4D2z2AWk_hlbP9yZg2gh57ZkLnwN2OBii');
hashJsonObject('SHA512', '16bFgJsInlap0tWJnLeDH8UUvZvBLUbrJrfiKLfseiGV5-RL_5MNDTzK8Y_IaIimB3DUXZxFGoU655GWPeoZjw');

assert.equal(Random.generateRandomNumber(5).length, 5);
assert.equal(Random.generateRandomNumber(64).length, 64);

logger.info('Done!');
