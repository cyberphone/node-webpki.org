'use strict';

const FS = require('fs');
const Crypto = require('crypto');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

function readKey(path) {
  return Keys.decodePrivateKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path).toString());
}

// Load a private key
const privateEcP256Key = readKey('private-p256-pkcs1.pem');

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Initiate the signer
var signer = new JCS.Signature(privateEcP256Key);

// Perform signing
var result = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(result));
