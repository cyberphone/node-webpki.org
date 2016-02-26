### JCS (JSON Cleartext Signatures) for "node.js"

Very early documentation

```JavaScript
'use strict';

const FS = require('fs');
const Crypto = require('crypto');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

function readKey(path) {
  return Keys.decodePrivateKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path));
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
```
Result (prettyfied for brevity but still cryptographically intact):
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
