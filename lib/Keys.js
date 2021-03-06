/*
 *  Copyright 2017-2020 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

/** Core methods for decoding and encoding asymmetric keys
 * @module Keys
 */

const Crypto = require('crypto');

const ByteArray = require('./ByteArray');
const Big       = require('./contrib/big/Big');
const JsonUtil  = require('./JsonUtil');
const Asn1      = require('./Asn1');
const Base64Url = require('./Base64Url');
 
const EC_CURVES = [
// CLength   Key Alg   Sign Aalg         ASN.1 OID (without header)
     32,     'P-256',  'ES256',   [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
     48,     'P-384',  'ES384',   [0x2B, 0x81, 0x04, 0x00, 0x22],
     66,     'P-521',  'ES512',   [0x2B, 0x81, 0x04, 0x00, 0x23]
];

const RSA_ALGORITHM_OID = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const EC_ALGORITHM_OID  = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; 

function getEcParamsFromCurve(curve) {
  for (var i = 0; i < EC_CURVES.length; i += 4) {
    if (EC_CURVES[i + 1] == curve) {
      return i;
    }
  }
  throw new TypeError('Unsupported EC curve: ' + curve);
}

function PublicKey(jwk, spki) {
  this.jwk = jwk;
  this.pem = '-----BEGIN PUBLIC KEY-----\n' +
             Buffer.from(spki).toString('base64') +
             '\n-----END PUBLIC KEY-----\n';
}

PublicKey.prototype.equals = function(publicKey) {
  if (publicKey) {
    if (publicKey instanceof PublicKey) {
      return this.pem == publicKey.pem;
    }
    throw new TypeError('Not "PublicKey"');
  }
  return false;
};

PublicKey.prototype.getSpki = function() {
  return getSpkiEncodedPublicKey(this.pem);
};

PublicKey.prototype.getJwk = function() {
  return JSON.stringify(this.jwk);
};

function encodeEcPublicKey(objectReader) {
  var curve = objectReader.getString('crv');
  var paramsEntry = getEcParamsFromCurve(curve);
  var xValue = objectReader.getBinary('x');
  var yValue = objectReader.getBinary('y');
  objectReader.checkForUnread();
  if (xValue.length != yValue.length || xValue.length != EC_CURVES[paramsEntry]) {
     throw new TypeError('Bad EC curve: ' + curve + ' x=' + xValue.length + ' y=' + yValue.length);
  }
  var ecPublicKeyBlob = ByteArray.add([0x04], ByteArray.add(xValue, yValue));
  var publicKey = new PublicKey(
    objectReader.getRootObject(),
    new Asn1.Encoder(Asn1.TAGS.SEQUENCE,
                     new Asn1.Encoder(Asn1.TAGS.SEQUENCE,
                                      new Asn1.Encoder(Asn1.TAGS.OID,
                                                       EC_ALGORITHM_OID))
                       .addComponent(new Asn1.Encoder(Asn1.TAGS.OID,
                                                      EC_CURVES[paramsEntry + 3])))
      .addComponent(new Asn1.Encoder(Asn1.TAGS.BITSTRING,
                                     ByteArray.add([0x00,],ecPublicKeyBlob)))
      .encode());
  // Ugly fix for dealing with Ecdh in the pretty broken 'Crypto' subsystem
  publicKey.ecPublicKeyBlob = ecPublicKeyBlob;
  return publicKey;
}

function getDefaultEcSignatureAlgorithm(curve) {
  return EC_CURVES[getEcParamsFromCurve(curve) + 2];
}

function createAsn1PositiveInteger(blobInteger) {
  while (blobInteger.length > 1 && blobInteger[0] == 0) {
    blobInteger = blobInteger.subarray(1);
  }
  if (blobInteger[0] > 127) {
    blobInteger = ByteArray.add([0], blobInteger);
  }
  return new Asn1.Encoder(Asn1.TAGS.INTEGER, blobInteger);
}

function encodeRsaPublicKey(objectReader) {
  var nValue = objectReader.getBinary('n');
  var eValue = objectReader.getBinary('e');
  objectReader.checkForUnread();
  return new PublicKey(
    objectReader.getRootObject(),
    new Asn1.Encoder(Asn1.TAGS.SEQUENCE,
                     new Asn1.Encoder(Asn1.TAGS.SEQUENCE,
                                      new Asn1.Encoder(Asn1.TAGS.OID,
                                                       RSA_ALGORITHM_OID))
                       .addComponent(new Asn1.Encoder(Asn1.TAGS.NULL, [])))
      .addComponent(new Asn1.Encoder(Asn1.TAGS.BITSTRING,
                                     ByteArray.add([0],
                                                   new Asn1.Encoder(Asn1.TAGS.SEQUENCE,
                                                                    createAsn1PositiveInteger(nValue))
                                                     .addComponent(createAsn1PositiveInteger(eValue))
                                                     .encode())))
      .encode());
}

function _encodePublicKey(objectReader) {
  var kty = objectReader.getString('kty');
  if (kty == 'RSA') {
    return encodeRsaPublicKey(objectReader);
  }
  if (kty == 'EC') {
    return encodeEcPublicKey(objectReader);
  }
  throw new TypeError('Unrecognized "kty" argument: ' + kty);
}

function encodePublicKey(jwk) {
  return _encodePublicKey(new JsonUtil.ObjectReader(jwk));
}

function getEcCurve(oid) {
  for (var i = 0; i < EC_CURVES.length; i += 4) {
    if (ByteArray.equals(EC_CURVES[i + 3], oid)) {
      return i;
    }
  }
  throw new TypeError('EC curve OID unknown');    
}

function createRsaJwk(nUndecoded, eUndecoded) {
  return new JsonUtil.ObjectReader(
    {kty: 'RSA',
     n: Base64Url.encode(nUndecoded.getAsn1PositiveInteger()),
     e: Base64Url.encode(eUndecoded.getAsn1PositiveInteger())}).scanItem('kty');
}

function decodePublicKeyFromSpki(spki) {
  var outerSequence = Asn1.decodeSequence(spki);
  if (outerSequence.numberOfComponents() != 2) {
    throw new TypeError('SubjectPublicKeyInfo sequence must be two elements');    
  }
  var algorithmId = outerSequence.getComponent(0).getAsn1Sequence();
  if (algorithmId.numberOfComponents() != 2) {
    throw new TypeError('Algorithm ID sequence must be two elements');    
  }
  var publicKeyType = algorithmId.getComponent(0).getAsn1ObjectIdRawData();
  var encapsulatedKey = outerSequence.getComponent(1).getAsn1BitString(true);
  if (ByteArray.equals(publicKeyType, RSA_ALGORITHM_OID)) {
    algorithmId.getComponent(1).getAsn1Null();
    var rsaParameters = Asn1.decodeSequence(encapsulatedKey);
    if (rsaParameters.numberOfComponents() != 2) {
      throw new TypeError('RSA parameter sequence must be two elements');    
    }
    return encodeRsaPublicKey(createRsaJwk(rsaParameters.getComponent(0),
                                           rsaParameters.getComponent(1)));
  }
  if (ByteArray.equals(publicKeyType, EC_ALGORITHM_OID)) {
    var curveIndex = getEcCurve(algorithmId.getComponent(1).getAsn1ObjectIdRawData());
    return encodeEcPublicKey(createEcJwk(curveIndex, encapsulatedKey));
  }
  throw new TypeError('Public key OID unknown');    
}

function getBinaryContentFromPem(pem, label, multiple) {
  if (Buffer.isBuffer(pem)) {
    pem = pem.toString();
  }
  var result = [];
  while (true) {
    var start = pem.indexOf('-----BEGIN ' + label + '-----');
    var end = pem.indexOf('-----END ' + label + '-----');
    if (start >= 0 && end > 0 && end > start) {
      var value = Buffer.from(pem.substring(start + label.length + 16, end), 'base64');
      result.push(multiple ? new Certificate(value) : value);
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

function PrivateKey(objectReader, pkcs1) {
  this.jwk = objectReader.getRootObject();
  this.pem = '-----BEGIN ' + this.jwk.kty + ' PRIVATE KEY-----\n' +
             Buffer.from(pkcs1).toString('base64') +
             '\n-----END ' + this.jwk.kty + ' PRIVATE KEY-----\n';
}

PrivateKey.prototype.getPublicKey = function() {
  return encodePublicKey(this.jwk);
};

PrivateKey.prototype.setKeyId = function(keyId) {
  this.keyId = keyId;
  return this;
};

PrivateKey.prototype.getKeyId = function() {
  return this.keyId;
};

function createEcJwk(curveIndex, publicKeyBlob) {
  if (publicKeyBlob[0] != 0x04) {
    throw new TypeError('EC uncompressed parameter expected');    
  }
  var coordinateLength = EC_CURVES[curveIndex];
  if (publicKeyBlob.length != coordinateLength * 2 + 1) {
    throw new TypeError('EcPoint length error');    
  }
  return new JsonUtil.ObjectReader(
     {kty: 'EC',
      crv: EC_CURVES[curveIndex + 1],
      x: Base64Url.encode(publicKeyBlob.subarray(1, 1 + coordinateLength)),
      y: Base64Url.encode(publicKeyBlob.subarray(1 + coordinateLength))}).scanItem('kty');
}

function decodeEcPrivateKey(pkcs1) {
  var ecParameters = Asn1.decodeSequence(pkcs1);
  checkInteger(ecParameters.getComponent(0).getAsn1Integer(), 1); // Public key version
  var curveIndex = getEcCurve(ecParameters.getComponent(2).getAsn1ExplicitContext(0).getAsn1ObjectIdRawData());
  var ecPrivateKeyBlob = ecParameters.getComponent(1).getAsn1OctetString();
  var privateKeyLength = EC_CURVES[curveIndex];
  if (ecPrivateKeyBlob.length != privateKeyLength) {
    throw new TypeError('EC private key length error');
  }
  var privateKey =
    new PrivateKey(createEcJwk(curveIndex,
                               ecParameters.getComponent(3).getAsn1ExplicitContext(1).getAsn1BitString(true)),
                   pkcs1);
  // Ugly fix for dealing with Ecdh in the pretty broken 'Crypto' subsystem
  privateKey.ecPrivateKeyBlob = ecPrivateKeyBlob;
  return privateKey;
}

function decodeRsaPrivateKey(pkcs1) {
  var rsaParameters = Asn1.decodeSequence(pkcs1);
  checkInteger(rsaParameters.getComponent(0).getAsn1Integer(), 0); // Public key version
  return new PrivateKey(
    createRsaJwk(rsaParameters.getComponent(1), rsaParameters.getComponent(2)),
    pkcs1);
}

function decodePrivateKey(pkcs8) {
  var outerSequence = Asn1.decodeSequence(pkcs8);
  if (outerSequence.numberOfComponents() != 3) {
    throw new TypeError('PKCS #8 sequence must be three elements');    
  }
  checkInteger(outerSequence.getComponent(0).getAsn1Integer(), 0); // PKCS #8 version
  var algorithmId = outerSequence.getComponent(1).getAsn1Sequence();
  if (algorithmId.numberOfComponents() != 2) {
    throw new TypeError('Algorithm ID sequence must be two elements');    
  }
  var publicKeyType = algorithmId.getComponent(0).getAsn1ObjectIdRawData();
  if (ByteArray.equals(publicKeyType, RSA_ALGORITHM_OID)) {
    return decodeRsaPrivateKey(outerSequence.getComponent(2).getAsn1OctetString());
  }
  if (ByteArray.equals(publicKeyType, EC_ALGORITHM_OID)) {
    return decodeEcPrivateKey(outerSequence.getComponent(2).getAsn1OctetString());
  }
  throw new TypeError('Unrecognized PKCS #8 key');
 }

function getSpkiEncodedPublicKey(pem) {
  return getBinaryContentFromPem(pem,'PUBLIC KEY', false);
}

function createPublicKeyFromPem(pem) {
  return decodePublicKeyFromSpki(getSpkiEncodedPublicKey(pem));
}

function createPrivateKeyFromPem(pem) {
  if (Buffer.isBuffer(pem)) {
    pem = pem.toString();
  }
  if (pem.includes('EC PRIVATE KEY')) {
    return decodeEcPrivateKey(getBinaryContentFromPem(pem,'EC PRIVATE KEY', false));
  }
  if (pem.includes('RSA PRIVATE KEY')) {
    return decodeRsaPrivateKey(getBinaryContentFromPem(pem,'RSA PRIVATE KEY', false));
  }
  return decodePrivateKey(getBinaryContentFromPem(pem,'PRIVATE KEY', false));
}

function createCertificatesFromPem(pem) {
  return getBinaryContentFromPem(pem,'CERTIFICATE', true);
}

function getEcSignatureCoordinate(length, component) {
  var value = component.getAsn1Integer();
  while (value.length > length) {
    if (value[0] != 0) {
      throw new TypeError('EC signature coordinate out of range');
    }
    value = value.subarray(1);
  }
  while (value.length < length) {
    value = ByteArray.add([0],value);
  }
  return value;
}

function ecDer2JoseSignature(rawValue, curve) {
  var length = EC_CURVES[getEcParamsFromCurve(curve)];
  var sequence = Asn1.decodeSequence(rawValue);
  if (sequence.numberOfComponents() != 2) {
    throw new TypeError('DER EC signature sequence must be two elements');    
  }
  return ByteArray.add(getEcSignatureCoordinate(length, sequence.getComponent(0)),
                       getEcSignatureCoordinate(length, sequence.getComponent(1)));
}

function ecJose2DerSignature(rawValue, curve) {
  var length = EC_CURVES[getEcParamsFromCurve(curve)];
  if (rawValue.length != length * 2) {
    throw new TypeError('JOSE EC signature length error' + rawValue.length);    
  }
  return new Asn1.Encoder(
    Asn1.TAGS.SEQUENCE,
    createAsn1PositiveInteger(rawValue.subarray(0, length)))
      .addComponent(createAsn1PositiveInteger(rawValue.subarray(length)))
      .encode();
}

function checkCertificatePath(certificatePath) {
  if (certificatePath === undefined || !Array.isArray(certificatePath) ||
      certificatePath.length == 0 || !(certificatePath[0] instanceof Certificate)) {
    throw new TypeError('Invalid certificate data');
  }
  for (var q = 1; q < certificatePath.length; q++) {
    if (!certificatePath[q - 1].isSignedBy(certificatePath[q])) {
      throw new TypeError('Certificate path error.  Wrong sorting order?');
    }
  }
  return certificatePath;
}

const X500_ATTRIBUTES = [
// Symbolic       ASN.1 OID (without header)
    'CN',       [0x55, 0x04, 0x03],
    'DC',       [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19],
    'OU',       [0x55, 0x04, 0x0B],
    'O',        [0x55, 0x04, 0x0A],
    'L',        [0x55, 0x04, 0x07],
    'ST',       [0x55, 0x04, 0x08],
    'STREET',   [0x55, 0x04, 0x09],
    'C',        [0x55, 0x04, 0x06]
];

const HASH_METHODS = [
//  Method       ASN.1 OID (without header)
    'sha256',    [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],  // ECDSA
    'sha384',    [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],  // ECDSA
    'sha512',    [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04],  // ECDSA
    'sha1'  ,    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05],  // RSA
    'sha256',    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],  // RSA
    'sha384',    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C],  // RSA
    'sha512',    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D]   // RSA
];

function getHashAlgorithmFromOID(rawOid) {
  for (var i = 1; i < HASH_METHODS.length; i += 2) {
    if (ByteArray.equals(rawOid, HASH_METHODS[i])) {
      return HASH_METHODS[i - 1];
    }
  }
  throw new TypeError('Unknown signature OID: ' + rawOid);
}

function getAttributeString(asn1Type) {
  var string = "";
  var data = asn1Type.getBodyData();
  for (var i = 0; i < data.length; i++) {
    var b = data[i];
    if (asn1Type.tag == Asn1.TAGS.UTF8STRING && b > 127) {
      var b2 = data[++i];
      if ((b & 0x20) == 0) {
        // Two byters
        var c = String.fromCharCode(((b & 0x1F) << 6) | (b2 & 0x3F));
      } else {
        // Three byters
        var b3 = data[++i];
        var c = String.fromCharCode(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F));
      }
    } else if (asn1Type.tag == Asn1.TAGS.BMPSTRING) {
      var c = String.fromCharCode((b << 8) | data[++i]);
    } else {
      var c = String.fromCharCode(b);
    }
    if (c == ',' || c == ';' || c == '+' || c == '=' || c == '\\') {
      string += '\\';
    }
    string += c;
  }
  return string;
}

function getDistinguishedName(asn1Sequence) {
  var dnHolder = asn1Sequence.getAsn1Sequence();
  var dn = "";
  var next = false;
  var q = dnHolder.numberOfComponents();
  while (--q >= 0) {
    if (next) {
      dn += ',';
    } else {
      next = true;
    }
    var set = dnHolder.getComponent(q).getAsn1Set();
    if (set.numberOfComponents() != 1) {
console.log('Multivalued, drop it');
      return null;
    }
    var attr = set.getComponent(0).getAsn1Sequence();
    if (attr.numberOfComponents() != 2) {
console.log('Weird, drop it');
      return null;
    }
    // Now it seems that we can try to do something sensible!
    var attrName = attr.getComponent(0).getAsn1ObjectIdRawData();
    var nonSymbolic = true;
    for (var i = 1; i < X500_ATTRIBUTES.length; i += 2) {
      if (ByteArray.equals(attrName, X500_ATTRIBUTES[i])) {
        nonSymbolic = false;
        dn += X500_ATTRIBUTES[i - 1] + '=' + getAttributeString(attr.getComponent(1));
        break;
      }
    }
    if (nonSymbolic) {
      var i = 0;
      var oid = null;
      while (i < attrName.length) {
        var subid = 0;
        do {
          subid = (subid << 7) + (attrName[i] &0x7F);
        } while ((attrName[i++] & 0x80) != 0);
        if (oid == null) {
          oid = (Math.floor(subid / 40)).toString();
          subid = Math.floor(subid % 40);
        }
        oid += '.' + subid;
      }
      dn += oid + '=#' + ByteArray.toHex(attr.getComponent(1).encode());
    }
  }
  return dn;
}

/**
 * X.509 certificate holder
 * @constructor
 * @param {(Uint8Array|Buffer)} certificateBlob - DER encoded certificate
 */
function Certificate(certificateBlob) {
  this.certificateBlob = certificateBlob;
  var asn1 = Asn1.decodeSequence(certificateBlob);
  if (asn1.numberOfComponents() != 3) {
    throw new TypeError('Malformed certificate');
  }
  var tbs = asn1.getComponent(0).getAsn1Sequence();
  var signatureAlgorithm = asn1.getComponent(1).getAsn1Sequence();
  if (signatureAlgorithm.numberOfComponents() != 2) {
    throw new TypeError('Malformed signature algorithm');
  }
  signatureAlgorithm.getComponent(1).getAsn1Null();
  this.tbs = tbs.encode();
  this.hashAlgorithm =
    getHashAlgorithmFromOID(this.signatureAlgorithm = 
                            signatureAlgorithm.getComponent(0).getAsn1ObjectIdRawData());
  this.signature = asn1.getComponent(2).getAsn1BitString(true);
  var index = 0;
  if (tbs.getComponent(0).getTag() == Asn1.TAGS.EXPLICIT_CONTEXT) {
    index++;  // V3
  }
  var serialNumber = new Big(0);
  tbs.getComponent(index++).getAsn1PositiveInteger().forEach((byte) => {
    serialNumber = serialNumber.times(256).plus(byte);
  });
  this.serialNumber = serialNumber;
  tbs.getComponent(index++).getAsn1Sequence();  // Signature alg, skip
  this.issuer = getDistinguishedName(tbs.getComponent(index++));
  if (this.issuer === undefined) {
    console.log('Couldn\'t decode issuer DN');
  }
  if (tbs.getComponent(index++).getAsn1Sequence().numberOfComponents() != 2) {
    throw new TypeError('Certificate validity not found');    
  }
  this.subject = getDistinguishedName(tbs.getComponent(index++));
  if (this.subject === undefined) {
    console.log('Couldn\'t decode subject DN');
  }
  this.publicKey = decodePublicKeyFromSpki(tbs.getComponent(index).getAsn1Sequence().encode());
}

/**
 * Get subject distinguished name
 * @return {string}
 */
Certificate.prototype.getSubject = function() {
  return this.subject;
};

/**
 * Get issuer distinguished name
 * @return {string}
 */
Certificate.prototype.getIssuer = function() {
  return this.issuer;
};

/**
 * Get serial number
 * @return {Big}
 */
Certificate.prototype.getSerialNumber = function() {
  return this.serialNumber;
};

Certificate.prototype.getPublicKey = function() {
  return this.publicKey;
};

Certificate.prototype.getCertificateBlob = function() {
  return this.certificateBlob;
};

Certificate.prototype.isSignedBy = function(certificate) {
  var verifier = Crypto.createVerify(this.hashAlgorithm);
  verifier.update(this.tbs);
  return verifier.verify(certificate.publicKey.pem, this.signature) &&
         this.getIssuer() == certificate.getSubject();
};


exports.PublicKey = PublicKey;
exports.PrivateKey = PrivateKey;
exports.Certificate = Certificate;
exports.encodePublicKey = encodePublicKey;
exports._encodePublicKey = _encodePublicKey;
exports.createPublicKeyFromPem = createPublicKeyFromPem;
exports.createPrivateKeyFromPem = createPrivateKeyFromPem;
exports.createCertificatesFromPem = createCertificatesFromPem;
exports.ecDer2JoseSignature = ecDer2JoseSignature;
exports.ecJose2DerSignature = ecJose2DerSignature;
exports.checkCertificatePath = checkCertificatePath;
exports.getDefaultEcSignatureAlgorithm = getDefaultEcSignatureAlgorithm;
