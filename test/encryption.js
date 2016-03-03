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

// Generate Alice's keys...
const alice = crypto.createECDH('secp521r1');
const alice_key = alice.generateKeys();

// Generate Bob's keys...
const bob = crypto.createECDH('secp521r1');
const bob_key = bob.generateKeys();

// Exchange and generate the secret...
const alice_secret = alice.computeSecret(bob_key);
const bob_secret = bob.computeSecret(alice_key);

assert.deepEqual(alice_secret, bob_secret);

function readFile(path) {
  return FS.readFileSync(__dirname + '/' + path).toString();
}

const receiver_private_key =
   Keys.createPrivateKeyFromPEM(readFile('private-p256-pkcs1.pem')).ecPrivateKeyBlob;
const receiver_public_key =
   Keys.createPublicKeyFromPEM(readFile('public-p256.pem')).ecPublicKeyBlob;

const receiver = crypto.createECDH('prime256v1');
receiver.setPrivateKey(receiver_private_key, 'binary');

const sender = crypto.createECDH('prime256v1');
const sender_public_key = sender.generateKeys('binary','uncompressed');
assert.equal(sender.computeSecret(receiver_public_key, 'binary', 'binary'),
             receiver.computeSecret(sender_public_key, 'binary', 'binary'));

// ECDH test data

const ECDH_RESULT_WITH_KDF       = 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc';
const ECDH_RESULT_WITHOUT_KDF    = 'SzFxLgluXyC07Pl5D9jMfIt-LIrZC9qByyJPYsDnuaY';
const JOSE_A128CBC_HS256_ALG_ID  = 'A128CBC-HS256';

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
                                                 JOSE_A128CBC_HS256_ALG_ID)), ECDH_RESULT_WITH_KDF);

// ECDH Ephemeral-Static
const ecStatic = new Encryption.ECDH(test_private_key);
const ecEphemeral = new Encryption.ECDH(test_private_key.getPublicKey());
assert.deepEqual(ecStatic.computeZ(ecEphemeral.getPublicKey()),
                 ecEphemeral.computeZ(test_private_key.getPublicKey()));
