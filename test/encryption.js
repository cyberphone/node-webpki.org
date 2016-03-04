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

// NOT READY

const crypto = require('crypto');
const assert = require('assert');
const FS = require('fs');

const Keys = require('../lib/keys');
const ByteArray = require('../lib/bytearray');
const Base64URL = require('../lib/base64url');
const Encryption = require('../lib/encryption');

// ECDH test data

const ECDH_RESULT_WITH_KDF       = 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc';
const ECDH_RESULT_WITHOUT_KDF    = 'SzFxLgluXyC07Pl5D9jMfIt-LIrZC9qByyJPYsDnuaY';

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
   Keys.createPrivateKeyFromPEM(ECHD_TEST_PRIVATE_KEY);
const test_public_key =
   Keys.createPublicKeyFromPEM(ECHD_TEST_PUBLIC_KEY);

// ECDH Static-Static
const ec1 = new Encryption.ECDH(test_private_key);
assert.equal(Base64URL.encode(ec1.computeZ(test_public_key)), ECDH_RESULT_WITHOUT_KDF);

// ECDH Static-Static
const ec2 = new Encryption.ECDH(test_private_key);
assert.equal(Base64URL.encode(ec2.computeWithKDF(test_public_key, 
                                                 Encryption.JOSE_A128CBC_HS256_ALG_ID)),
             ECDH_RESULT_WITH_KDF);

// ECDH Ephemeral-Static
const ecStatic = new Encryption.ECDH(test_private_key);
const ecEphemeral = new Encryption.ECDH(test_private_key.getPublicKey());
assert.deepEqual(ecStatic.computeZ(ecEphemeral.getPublicKey()),
                 ecEphemeral.computeZ(test_private_key.getPublicKey()));
                 
// ECDH Ephemeral-Ephemeral

function readPublicKey(path) {
  return Keys.createPrivateKeyFromPEM(FS.readFileSync(__dirname + '/' + path)).getPublicKey();
}

function ephemeralEphemeral(publicKey) {
  var one = new Encryption.ECDH(publicKey);
  var two = new Encryption.ECDH(publicKey);
  assert.deepEqual(one.computeZ(two.getPublicKey()),
                   two.computeZ(one.getPublicKey()));
}
                   
ephemeralEphemeral(readPublicKey('private-ec-p521-key.pem'));
ephemeralEphemeral(readPublicKey('private-p256-pkcs1.pem'));
ephemeralEphemeral(readPublicKey('mybank-cert-and-key-p256.pem'));

