'use strict';

const FS = require('fs');
const Crypto = require('crypto');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

// Load private key and certificate path
const keyData = FS.readFileSync(__dirname + '/test/mybank-cert-and-key-p256.pem');
const privateKey = Keys.createPrivateKeyFromPEM(keyData);
const certificatePath = Keys.createCertificatePathFromPEM(keyData);

// Initiate the signer
var signer = new JCS.Signer(privateKey);

// Indicate that we want to include a certificate path
signer.setCertificatePath(certificatePath, true);

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(signedJavaScript));

// Now we could verify the signed object we just created

// Create a verifier object
var verifier = new JCS.Verifier();

// Call decoding.  This will check that signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the anticipated key was used
//console.log('Validation success=' + result.verifyPublicKey(publicKey));
