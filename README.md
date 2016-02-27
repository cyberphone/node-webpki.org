### JCS (JSON Cleartext Signature) for "node.js"

Very early documentation

## Create a signed object
```JavaScript
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
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(signedJavaScript));
```json
{
  "statement": "Hello signed world!",
  "signature": {
    "algorithm": "ES256",
    "publicKey": {
      "type": "EC",
      "curve": "P-256",
      "x": "67f720OvQfRJaolZjIz_l-5qkCCJ0wK9MljNCOga-00",
      "y": "rDase7PLLOrppIfJpSHdj8vIjVz1BAi8tIFR0fmeyLY"
    },
    "value": "ie7k1zVY4eGBjCJz9z7c9wbkd5r5MW8Yu9zkJF3Jyy2sRww9kdFqJux-BiK02FCnBTn43Pz4NQMdlScIP9NhVA"
  }
}
```

## Validate a signature
```javascript
// Now we could verify the signed object we just created

function readPublicKey(path) {
  return Keys.createPublicKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path));
}

// Load a matching public key
const publicKey = readPublicKey('public-p256.pem');

// Create a verifier object
var verifier = new JCS.Verifier();

// Call decoding.  This will check that signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the anticipated key was used
console.log('Validation success=' + result.verifyPublicKey(publicKey));
```
