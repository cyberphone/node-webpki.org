'use strict';

const Jcs = require('webpki.org').Jcs;

// Define a suitable secret key
var secretKey = new Buffer('F4C74F3398C49CF46D93EC9818832661A40BAE4D204D75503614102074346909', 'hex');

// Initiate the signer with key and algorithm.  Finally, add an (optional) keyId
var signer = new Jcs.Signer(secretKey, 'HS256').setKeyId('mykey');

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(signedJavaScript));

// Now we could verify the signed object we just created

// Create a verifier object
var verifier = new Jcs.Verifier();

// Call decoding.  This will check that signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check the result
console.log('Validation success=' + result.verifyHmac(secretKey));
