'use strict';

const Fs = require('fs');

const Keys = require('webpki.org').Keys;
const Jcs = require('webpki.org').Jcs;
const JsonUtil = require('webpki.org').JsonUtil;

function readPrivateKey(path) {
  return Keys.createPrivateKeyFromPem(Fs.readFileSync(__dirname + '/test/' + path));
}

// Load a private key
const privateKey = readPrivateKey('private-p256-pkcs8.pem');

// Initiate the signer
var signer = new Jcs.Signer(privateKey);

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as "pretty" (but legal) JSON.
// JSON.stringify(signedJavaScript) would be a better choice for sending JSON to external parties. 
console.log(JsonUtil.prettyPrint(signedJavaScript));

// Now we could verify the signed object we just created

function readPublicKey(path) {
  return Keys.createPublicKeyFromPem(Fs.readFileSync(__dirname + '/test/' + path));
}

// Load a matching public key
const publicKey = readPublicKey('public-p256.pem');

// Create a verifier object
var verifier = new Jcs.Verifier();

// Call decoding.  This will check that signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the anticipated key was used
console.log('Validation success=' + result.verifyPublicKey(publicKey));
