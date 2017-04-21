'use strict';

const Fs = require('fs');

const Keys     = require('webpki.org').Keys;
const Jcs      = require('webpki.org').Jcs;
const JsonUtil = require('webpki.org').JsonUtil;

// Load private key and certificate path
const keyData = Fs.readFileSync(__dirname + '/test/mybank-cert-and-key-p256.pem');
const privateKey = Keys.createPrivateKeyFromPem(keyData);
const certificatePath = Keys.createCertificatesFromPem(keyData);

// Initiate the signer
var signer = new Jcs.Signer(privateKey);

// Indicate that we want to include a certificate path
signer.setCertificatePath(certificatePath, true);

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as "pretty" (but legal) JSON.
console.log(JsonUtil.prettyPrint(signedJavaScript));

// Now we could verify the signed object we just created

// Load trust store
const trustedCAs = Keys.createCertificatesFromPem(Fs.readFileSync(__dirname + '/test/payment-network-ca.pem'));

// Create a verifier object
var verifier = new Jcs.Verifier();

// Call decoding.  This will check that signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the certificate path is trusted (true)
console.log('Validation success=' + result.verifyTrust(trustedCAs));

// Now check if the client certificate is root (false)
console.log('Validation success=' + result.verifyTrust([result.getCertificatePath()[0]]));

// Now check if the certificate path holds the root (true)
console.log('Validation success=' + result.verifyTrust([result.getCertificatePath()[result.getCertificatePath().length - 1]]));
