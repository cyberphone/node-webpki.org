'use strict';

const FS = require('fs');
const Crypto = require('crypto');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

function readPrivateKey(path) {
  return Keys.createPrivateKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path));
}

// Load a private key
const privateKey = readPrivateKey('private-p256-pkcs1.pem');

// Initiate the signer
var signer = new JCS.Signature(privateKey);

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var result = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(result));
