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
/*                              Keys                              */
/*================================================================*/

// Core methods for decoding and encoding asymmetric keys.

var ByteArray = require('./bytearray');
var ASN1 = require('./asn1');
var Base64URL = require('./base64url');
 
const EC_CURVES = [
// CLength   JOSE ALG     ASN.1 OID (without header)
     32,     'P-256',   [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
     48,     'P-384',   [0x2B, 0x81, 0x04, 0x00, 0x22],
     66,     'P-521',   [0x2B, 0x81, 0x04, 0x00, 0x23]
];

const RSA_ALGORITHM_OID    = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const EC_ALGORITHM_OID     = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; 

function getECParamsFromCurve(curve) {
  for (var i = 0; i < EC_CURVES.length; i += 3) {
    if (EC_CURVES[i + 1] == curve) {
      return i;
    }
  }
  throw new TypeError('Unsupported EC curve: ' + curve);
}

function PublicKey(jcs, spki) {
  this.jcs = jcs;
  this.pem = '-----BEGIN PUBLIC KEY-----\n' +
             new Buffer(spki).toString('base64') +
             '\n-----END PUBLIC KEY-----\n';
}

function checkForExtras(jcs, expected) {
  for (var key in jcs) {
    expected--;
  }
  if (expected) {
    throw new TypeError('Invalid JCS key: ' + JSON.stringify(jcs));
  }
} 

function encodeECPublicKey(jcs) {
  checkForExtras(jcs, 4);
  var paramsEntry = getECParamsFromCurve(jcs.curve);
  var xValue = Base64URL.decode(jcs.x);
  var yValue = Base64URL.decode(jcs.y);
  if (xValue.length != yValue.length || xValue.length != EC_CURVES[paramsEntry]) {
     throw new TypeError('Bad EC curve: ' + curve + ' x=' + xValue.length + ' y=' + yValue.length);
  }
  return new PublicKey(
    jcs,
    new ASN1.Encoder(ASN1.TAGS.SEQUENCE,
                     new ASN1.Encoder(ASN1.TAGS.SEQUENCE,
                                      new ASN1.Encoder(ASN1.TAGS.OID,
                                                       EC_ALGORITHM_OID))
                       .addComponent(new ASN1.Encoder(ASN1.TAGS.OID,
                                                      EC_CURVES[paramsEntry + 2])))
      .addComponent(new ASN1.Encoder(ASN1.TAGS.BITSTRING,
                                     ByteArray.add([0x00, 0x04],
                                                   ByteArray.add(xValue, yValue))))
      .encode());
}

function createASN1PositiveInteger(blobInteger) {
  if (blobInteger[0] > 127) {
    blobInteger = ByteArray.add([0], blobInteger);
  }
  return new ASN1.Encoder(ASN1.TAGS.INTEGER, blobInteger);
}

function encodeRSAPublicKey(jcs) {
  checkForExtras(jcs, 3);
  var nValue = Base64URL.decode(jcs.n);
  var eValue = Base64URL.decode(jcs.e);
  return new PublicKey(
    jcs,
    new ASN1.Encoder(ASN1.TAGS.SEQUENCE,
                     new ASN1.Encoder(ASN1.TAGS.SEQUENCE,
                                      new ASN1.Encoder(ASN1.TAGS.OID,
                                                       RSA_ALGORITHM_OID))
                       .addComponent(new ASN1.Encoder(ASN1.TAGS.NULL, [])))
      .addComponent(new ASN1.Encoder(ASN1.TAGS.BITSTRING,
                                     ByteArray.add([0],
                                                   new ASN1.Encoder(ASN1.TAGS.SEQUENCE,
                                                                    createASN1PositiveInteger(nValue))
                                                     .addComponent(createASN1PositiveInteger(eValue))
                                                     .encode())))
      .encode());
}

function encodePublicKey(jcs) {
  if (jcs.type == 'RSA') {
    return encodeRSAPublicKey(jcs);
  }
  if (jcs.type == 'EC') {
    return encodeECPublicKey(jcs);
  }
  throw new TypeError('"type" doesn\'t contain a valid key type');
}

function getEcCurve(oid) {
  for (var i = 0; i < EC_CURVES.length; i += 3) {
    if (ByteArray.equals(EC_CURVES[i + 2], oid)) {
      return i;
    }
  }
  throw new TypeError('EC curve OID unknown');    
}

function createRsaJcs(nUndecoded, eUndecoded) {
  return {type: 'RSA',
          n: Base64URL.encode(nUndecoded.getASN1PositiveInteger()),
          e: Base64URL.encode(eUndecoded.getASN1PositiveInteger())};
}

function decodePublicKeyFromSPKI(spki) {
  var outerSequence = ASN1.decodeSequence(spki);
  if (outerSequence.numberOfComponents() != 2) {
    throw new TypeError('SubjectPublicKeyInfo sequence must be two elements');    
  }
  var algorithmId = outerSequence.getComponent(0).getASN1Sequence();
  if (algorithmId.numberOfComponents() != 2) {
    throw new TypeError('Algorithm ID sequence must be two elements');    
  }
  var publicKeyType = algorithmId.getComponent(0).getASN1ObjectIDRawData();
  var encapsulatedKey = outerSequence.getComponent(1).getASN1BitString(true);
  if (ByteArray.equals(publicKeyType, RSA_ALGORITHM_OID)) {
    algorithmId.getComponent(1).getASN1NULL();
    var rsaParameters = ASN1.decodeSequence(encapsulatedKey);
    if (rsaParameters.numberOfComponents() != 2) {
      throw new TypeError('RSA parameter sequence must be two elements');    
    }
    return encodeRSAPublicKey(createRsaJcs(rsaParameters.getComponent(0),
                                           rsaParameters.getComponent(1)));
  }
  if (ByteArray.equals(publicKeyType, EC_ALGORITHM_OID)) {
    var curveIndex = getEcCurve(algorithmId.getComponent(1).getASN1ObjectIDRawData());
    return encodeECPublicKey(createEcJcs(curveIndex, encapsulatedKey));
  }
  throw new TypeError('Public key OID unknown');    
}

function getBinaryContentFromPEM(pem, label, multiple) {
  if (Buffer.isBuffer(pem)) {
    pem = pem.toString();
  }
  var result = [];
  while (true) {
    var start = pem.indexOf('-----BEGIN ' + label + '-----');
    var end = pem.indexOf('-----END ' + label + '-----');
    if (start >= 0 && end > 0 && end > start) {
      result.push(new Buffer(pem.substring(start + label.length + 16, end), 'base64'));
      pem = pem.substring(end + label.length + 14);
    } else {
      if (result.length == 0) {
        throw new TypeError('No "' + label + '" found');
      }
      if (multiple) {
        return result;
      }
      if (result.length > 1) {
        throw new TypeError('Multiple "' + label + '" found');
      }
      return result[0];
    }
  }
}

function checkInteger(data, value) {
  if (data.length != 1 || data[0] != value) {
    throw new TypeError('Expected: ' + value + ' got: ' + data);
  }
}

function PrivateKey(jcs, pkcs1) {
  this.jcs = jcs;
  this.pem = '-----BEGIN ' + jcs.type + ' PRIVATE KEY-----\n' +
             new Buffer(pkcs1).toString('base64') +
             '\n-----END ' + jcs.type + ' PRIVATE KEY-----\n';
}

function createEcJcs(curveIndex, publicKeyBlob) {
  if (publicKeyBlob[0] != 0x04) {
    throw new TypeError('EC uncompressed parameter expected');    
  }
  var coordinateLength = EC_CURVES[curveIndex];
  if (publicKeyBlob.length != coordinateLength * 2 + 1) {
    throw new TypeError('ECPoint length error');    
  }
  return {type: 'EC',
          curve: EC_CURVES[curveIndex + 1],
          x: Base64URL.encode(new Uint8Array(publicKeyBlob.subarray(1, 1 + coordinateLength))),
          y: Base64URL.encode(new Uint8Array(publicKeyBlob.subarray(1 + coordinateLength)))};
}

function decodeECPrivateKey(pkcs1) {
  var ecParameters = ASN1.decodeSequence(pkcs1);
  checkInteger(ecParameters.getComponent(0).getASN1Integer(), 1); // Public key version
  var curveIndex = getEcCurve(ecParameters.getComponent(2).getASN1ExplicitContext(0).getASN1ObjectIDRawData());
  if (ecParameters.getComponent(1).getASN1OctetString().length != EC_CURVES[curveIndex]) {
    throw new TypeError('EC private key length error');
  }
  return new PrivateKey(
    createEcJcs(curveIndex,
                ecParameters.getComponent(3).getASN1ExplicitContext(1).getASN1BitString(true)),
    pkcs1);
}

function decodeRSAPrivateKey(pkcs1) {
  console.log('RSA!');
  var rsaParameters = ASN1.decodeSequence(pkcs1);
  checkInteger(rsaParameters.getComponent(0).getASN1Integer(), 0); // Public key version
  return new PrivateKey(
    createRsaJcs(rsaParameters.getComponent(1), rsaParameters.getComponent(2)),
    pkcs1);
}

function decodePrivateKey(pkcs8) {
  var outerSequence = ASN1.decodeSequence(pkcs8);
  if (outerSequence.numberOfComponents() != 3) {
    throw new TypeError('PKCS #8 sequence must be three elements');    
  }
  checkInteger(outerSequence.getComponent(0).getASN1Integer(), 0); // PKCS #8 version
  var algorithmId = outerSequence.getComponent(1).getASN1Sequence();
  if (algorithmId.numberOfComponents() != 2) {
    throw new TypeError('Algorithm ID sequence must be two elements');    
  }
  var publicKeyType = algorithmId.getComponent(0).getASN1ObjectIDRawData();
  if (ByteArray.equals(publicKeyType, RSA_ALGORITHM_OID)) {
    return decodeRSAPrivateKey(outerSequence.getComponent(2).getASN1OctetString());
  }
  if (ByteArray.equals(publicKeyType, EC_ALGORITHM_OID)) {
    return decodeECPrivateKey(outerSequence.getComponent(2).getASN1OctetString());
  }
  throw new TypeError('Unrecognized PKCS #8 key');
 }

function createPublicKeyFromPEM(pem) {
  return decodePublicKeyFromSPKI(getBinaryContentFromPEM(pem,'PUBLIC KEY', false));
}

function createPrivateKeyFromPEM(pem) {
  if (Buffer.isBuffer(pem)) {
    pem = pem.toString();
  }
  if (pem.includes('EC PRIVATE KEY')) {
    return decodeECPrivateKey(getBinaryContentFromPEM(pem,'EC PRIVATE KEY', false));
  }
  if (pem.includes('RSA PRIVATE KEY')) {
    return decodeRSAPrivateKey(getBinaryContentFromPEM(pem,'RSA PRIVATE KEY', false));
  }
  return decodePrivateKey(getBinaryContentFromPEM(pem,'PRIVATE KEY', false));
}

function createCertificatePathFromPEM(pem) {
  return getBinaryContentFromPEM(pem,'CERTIFICATE', true);
}

function getEcSigElem(length, value) {
  while (value.length > length) {
    if (value[0] != 0) {
      throw new TypeError('EC signature element out of range');
    }
    value = value.subarray(1);
  }
  while (value.length < length) {
    value = ByteArray.add([0],value);
  }
  return value;
}

function ecDer2Jose(rawValue, curve) {
  var length = EC_CURVES[getECParamsFromCurve(curve)];
  var sequence = ASN1.decodeSequence(rawValue);
  if (sequence.numberOfComponents() != 2) {
    throw new TypeError('Signature sequence must be two elements');    
  }
  return ByteArray.add(getEcSigElem(length, sequence.getComponent(0).getASN1Integer()),
                       getEcSigElem(length, sequence.getComponent(1).getASN1Integer()));
}

exports.PublicKey = PublicKey;
exports.PrivateKey = PrivateKey;
exports.encodePublicKey = encodePublicKey;
exports.createPublicKeyFromPEM = createPublicKeyFromPEM;
exports.createPrivateKeyFromPEM = createPrivateKeyFromPEM;
exports.createCertificatePathFromPEM = createCertificatePathFromPEM;
exports.ecDer2Jose = ecDer2Jose;
