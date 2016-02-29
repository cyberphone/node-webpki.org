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

// Generate Alice's keys...
const alice = crypto.createECDH('secp521r1');
const alice_key = alice.generateKeys();

// Generate Bob's keys...
const bob = crypto.createECDH('secp521r1');
const bob_key = bob.generateKeys();

// Exchange and generate the secret...
const alice_secret = alice.computeSecret(bob_key);
const bob_secret = bob.computeSecret(alice_key);

assert(alice_secret, bob_secret);

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
assert(sender.computeSecret(receiver_public_key, 'binary', 'binary'),
receiver.computeSecret(sender_public_key, 'binary', 'binary'));
