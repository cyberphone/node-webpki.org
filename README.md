# JCS (JSON Cleartext Signature) for "node.js"

Very early documentation, stay tuned :-)

JCS rationale: https://cyberphone.github.io/openkeystore/resources/docs/jsonsignatures.html<br>
JCS specification: https://cyberphone.github.io/openkeystore/resources/docs/jcs.html

### Installation

There is no npm yet but you can test this code anyway by downloading the zip
https://github.com/cyberphone/node-webpki.org/archive/master.zip
to a free directory and then perform three steps:
```bat
C:\node-webpki.org-master>mkdir node_modules
C:\node-webpki.org-master>mkdir node_modules\webpki.org
C:\node-webpki.org-master>copy package.json node_modules\webpki.org
```

Then you should be able to run the supplied demo and test programs:
```bat
C:\node-webpki.org-master>node democert.js
{"statement":"Hello signed world!", etc etc etc}
Validation success=true
```

### Create a signed object

```JavaScript
'use strict';

const FS = require('fs');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

function readPrivateKey(path) {
  return Keys.createPrivateKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path));
}

// Load a private key
const privateKey = readPrivateKey('private-p256-pkcs1.pem');

// Initiate the signer
var signer = new JCS.Signer(privateKey);

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(signedJavaScript));
```

### Resulting JSON string
(edited a bit for readability reasons while still being cryptographically correct)

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

### Validate a signature

```javascript
// Now we could verify the signed object we just created

function readPublicKey(path) {
  return Keys.createPublicKeyFromPEM(FS.readFileSync(__dirname + '/test/' + path));
}

// Load a matching public key
const publicKey = readPublicKey('public-p256.pem');

// Create a verifier object
var verifier = new JCS.Verifier();

// Call decoding.  This will check that the signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the anticipated key was used
console.log('Validation success=' + result.verifyPublicKey(publicKey));
```

###Using Certificates

Creating signatures with certificate paths is almost identical to
signatures only using public keys.  You simply need to add the path.

```javascript
'use strict';

const FS = require('fs');

const Keys = require('webpki.org').Keys;
const JCS = require('webpki.org').JCS;

// Load private key and certificate path
const keyData = FS.readFileSync(__dirname + '/test/mybank-cert-and-key-p256.pem');
const privateKey = Keys.createPrivateKeyFromPEM(keyData);
const certificatePath = Keys.createCertificatesFromPEM(keyData);

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

```

This sample would generate the following (albeit a bit "beautified") JSON:

```json
{
  "statement": "Hello signed world!",
  "signature": {
    "algorithm": "ES256",
    "signerCertificate": {
      "issuer": "CN=Payment Network Sub CA3,C=EU",
      "serialNumber": "1441094164079",
      "subject": "CN=mybank.com,2.5.4.5=#130434353031,C=FR"
    },
    "certificatePath": [
      "MIIBtTCCAVmgAwIBAgIGAU-H595vMAwGCCqGSM49BAMCBQAwLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMB4XDTE0MDEwMTAwMDAwMFoXDTIwMDcxMDA5NTk1OVowMTELMAkGA1UEBhMCRlIxDTALBgNVBAUTBDQ1MDExEzARBgNVBAMTCm15YmFuay5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASjhSNHJyRmQi5U-r7WkNns0D6b1n1gQybglCvyXgIA2RCSJXJKHZrw37giKmGqX-4cXU3x__zOQXN1U48VAwNvo10wWzAJBgNVHRMEAjAAMA4GA1UdDwEB_wQEAwIHgDAdBgNVHQ4EFgQUOdV3H3r6TufkQh-dqhcXMrjUY2kwHwYDVR0jBBgwFoAUy0fdXq1oJ6GFAJo10qx609KDARAwDAYIKoZIzj0EAwIFAANIADBFAiEAluqzuTTzVBG74AoALaWRsRn9QALg2N6C3sIlztm6sPoCID1ZnGnTrhz-CodxuGvg7fkOVfdffdSuEdyhQXemGtT4",
      "MIIDcjCCAVqgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAwMQswCQYDVQQGEwJVUzEhMB8GA1UEAxMYUGF5bWVudCBOZXR3b3JrIFJvb3QgQ0ExMB4XDTEyMDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcX8CYrYFoQhPbTci93W5qyCx0i0H-FvmXIvH5XNBlnNLfPkRacqn0PRFNn4Z4o3BVxI3x5yob9C7FqpKslcCgKNjMGEwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMtH3V6taCehhQCaNdKsetPSgwEQMB8GA1UdIwQYMBaAFELvwS_Fk7IfHMWJeu-yhGdM-5EiMA0GCSqGSIb3DQEBDQUAA4ICAQBNQdIOSU2fB5JjCO9Q0mCfOxDXFihMKSiOanAJ_r2rxGN7Uprw32JPsJnQhuxbrwmniKgCmBVD6Jak4GtHSLVvJPjpf_Pe7pUbyMb6iNNeV3SmJvsHoE2m5WdSGxjIPxK4NOBv3Mm3Ib1_kxyVceegHEHRUk5IXyQUNV1sUsxIypELjC8bAIvnMj_J1FlP8nsfehbibT3XH04uvX9dgNGexpz8BDLa0fEpLzrKoyMtUbSwg88_WsdPnkvp1fhiwCF9GpIHwsXi3Nv-Wdgdyn-hKFQe6sP2FmsPDiI2qWqX7fEs0VN5Uo2oI5Q2T6673JiZnkycXYLNIRpc06KSTcs8B45u5NMAyvLx3l4S8My-HK4nfiqbF3TPVGJkq4aXAAZnhVcQTrO71tQ0BJMibKjz6sylBEnhlFQs3ICcesaGVXV3JVbwtf_OkAUUUduYWOmUZU5ng3vNJV0ofqfvoNcBlVsrWpFNqImy2-icUxiad_8--ortiq4WG594Ap52CqXt7K8UcZaMLDAj2COOmo1gy9iUjzgyzSqnYye2Gqr72ts5jd8B8wkM1rM0JDM6DvCyJgHVvc8VTNE7Mt2Mu9XsofQkdLdDgrPuo6AV88g1BGk7cY0FJMJFoBAlrj98A4KslbeGBV7AUGuzvS-w1VA6dRH6_5Fv2eSHXW6pzA_D8Q"
    ],
    "value": "dBnkOuspGDc63aSWkXnXFPsdd2w8EpKl-01FbhO2v-oqVZ4JHUtHWP76qX04DqUJJWKy8Kw47jmKpAwkET2O0w"
  }
}
```

###Validation of Certificate Paths

Validation requires that you provide a collection of CA certificates.

```javascript
// Now we could verify the signed object we just created

// Load trust store
const trustedCAs = Keys.createCertificatesFromPEM(FS.readFileSync(__dirname + '/test/payment-network-ca.pem'));

// Create a verifier object
var verifier = new JCS.Verifier();

// Call decoding.  This will check that the signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check if the certificate path is trusted
console.log('Validation success=' + result.isTrusted(trustedCAs));
```

###HMAC Signatures

```javascript
'use strict';

const JCS = require('webpki.org').JCS;

// Define a suitable secret key
var secretKey = new Buffer('F4C74F3398C49CF46D93EC9818832661A40BAE4D204D75503614102074346909', 'hex');

// Initiate the signer with key and algorithm.  Finally, add an (optional) keyId
var signer = new JCS.Signer(secretKey, 'HS256').setKeyId('mykey');

// Create an object to sign
var jsonObject = {'statement':'Hello signed world!'};

// Perform signing
var signedJavaScript = signer.sign(jsonObject);

// Print it on the console as JSON
console.log(JSON.stringify(signedJavaScript));

// Now we could verify the signed object we just created

// Create a verifier object
var verifier = new JCS.Verifier();

// Call decoding.  This will check that the signature is technically correct
var result = verifier.decodeSignature(signedJavaScript);

// Now check the result
console.log('Validation success=' + result.verifyHmac(secretKey));
```

And here is the result (after "beautifying")... 

```json
{
  "statement": "Hello signed world!",
  "signature": {
    "algorithm": "HS256",
    "keyId": "mykey",
    "value": "IcC43Ecr11NPF01n6pj540OYvpVeUp3-wyxJ_cY_Yf4"
  }
}
```
