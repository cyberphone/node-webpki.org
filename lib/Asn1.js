/*
 *  Copyright 2006-2017 WebPKI.org (http://webpki.org).
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
/*                            Asn1                                */
/*================================================================*/

/** Ultra-light ASN.1 library
 * @module Asn1
 */


var ByteArray = require('./ByteArray');

/**
 * ASN.1 tag constants
 * @namespace
 */
const TAGS = {
    /**
     * @public
     */
    OID                : 0x06,
    /**
     * @public
     */
    SEQUENCE           : 0x30,
    /**
     * @public
     */
    SET                : 0x31,
    /**
     * @public
     */
    INTEGER            : 0x02,
    /**
     * @public
     */
    NULL               : 0x05,
    /**
     * @public
     */
    BITSTRING          : 0x03,
    /**
     * @public
     */
    UTF8STRING         : 0x0C,
    /**
     * @public
     */
    BMPSTRING          : 0x1E,
    /**
     * @public
     */
    EXPLICIT_CONTEXT   : 0xA0,
    /**
     * @public
     */
    OCTET_STRING       : 0x04
};

const LIBRARY_LIMIT = 50000;  // 50k of ASN.1 is all we care of

function _lengthCheck(length) {
  if (length > LIBRARY_LIMIT) {
    throw new TypeError('Exceeded library limit ' + LIBRARY_LIMIT + ' bytes');
  }
}

/**
 * Create ASN1 encoder
 * @constructor
 * @param {number} tag - ASN1 tag value
 * @param {(Encoder|Uint8Array)} argument - Encoder or DER binary
 */
function Encoder(tag, argument) {
  this.components = [];
  this.components.push(argument);
  this.tag = tag;
}

/**
 * Add component
 * @param {(Encoder|Uint8Array)} component - Encoder or DER binary
 * @return {this}
 */
Encoder.prototype.addComponent = function(component) {
  this.components.push(component);
  return this;
};

/**
 * Encode ASN.1 object to DER binary
 * @return {Uint8Array}
 */
Encoder.prototype.encode = function() {
  this.encoded = new Uint8Array();
  for (var i = 0; i < this.components.length; i++) {
    if (this.components[i] instanceof Encoder) {
      this._update(this.components[i].encode()); 
    } else {
      this._update(this.components[i]);
    }
  }
  var body = this.encoded;
  var length = body.length;
  this.encoded = new Uint8Array([this.tag, length & 0x7F]);
  if (length > 127) {
    if (length > 255) {
      this.encoded[1] = 0x82;
      this._update([length >> 8]);
    } else {
      this.encoded[1] = 0x81;
    }
    this._update([length & 0xFF]);
  }
  return this._update(body);
};

Encoder.prototype._update = function(array) {
  return this.encoded = ByteArray.add(this.encoded, array);
};

/**
 * Create ASN1 decoder
 * @constructor
 * @param {(Buffer|Uint8Array)} rawDerString - DER binary
 */
function Decoder(rawDerString) {
  _lengthCheck(rawDerString.length);
  this.rawDerString = rawDerString;
  this.position = 0;
  this.tag = this._readDerByte();
  var length = this._readDerByte();
  if ((length & 0x80) != 0) {
    var bytes = length & 0x7F;
    length = 0;
    while (bytes-- > 0) {
      length <<= 8;
      length += this._readDerByte();
      _lengthCheck(length);
    }
  }
  this.startOfBody = this.position;
  this.body = new Uint8Array(length);
  for (var i = 0; i < length; i++) {
    this.body[i] = this._readDerByte(); 
  }
  if (this.tag == TAGS.SEQUENCE || this.tag == TAGS.SET) {
    this.components = [];
    var newDerString = this.body;
    while (newDerString.length != 0) {
      var asn1Object = new Decoder(newDerString);
      var chunk = asn1Object.body.length + asn1Object.startOfBody; 
      this.components.push(asn1Object);
      if (chunk > newDerString.length) {
        throw new TypeError('Length error for tag: ' + asn1Object.tag);
      }
      newDerString = new Uint8Array(newDerString.subarray(chunk));
    }
  } else if (length == 0 && this.tag != TAGS.NULL) {
    throw new TypeError('Zero-length body not permitted for tag: ' + this.tag);
  }
  return this;
}

Decoder.prototype._readDerByte = function() {
  if (this.position >= this.rawDerString.length) {
    throw new TypeError('Buffer underrun for tag: ' + this.tag);
  }
  return this.rawDerString[this.position++];
};

/**
 * Get number of ASN.1 components found
 * @return {number}
 */
Decoder.prototype.numberOfComponents = function() {
  if (this.components === undefined) {
    throw new TypeError('This object type doesn\'t have components: ' + this.tag);
  }
  return this.components.length;
};

/**
 * Get component
 * @param {number} index - Component number (0..n)
 * @return {Decoder}
 */
Decoder.prototype.getComponent = function(index) {
  if (index >= this.numberOfComponents ()) {
    throw new TypeError('Component index out of range: ' + index);
  }
  return this.components[index];
};

/**
 * Get ASN.1 Object ID raw byte array
 * @return {Uint8Array}
 */
Decoder.prototype.getAsn1ObjectIdRawData = function() {
  return this._getBodyData(TAGS.OID);
};

/**
 * Get ASN.1 Integer raw byte array
 * @return {Uint8Array}
 */
Decoder.prototype.getAsn1Integer = function() {
  return this._getBodyData(TAGS.INTEGER);
};

/**
 * Get ASN.1 Octet String raw byte array
 * @return {Uint8Array}
 */
Decoder.prototype.getAsn1OctetString = function() {
  return this._getBodyData(TAGS.OCTET_STRING);
};

/**
 * Get ASN.1 Explicit Context object
 * @param {number} context - Context ID
 * @return {Decoder}
 */
Decoder.prototype.getAsn1ExplicitContext = function(context) {
  return new Decoder(this._getBodyData(TAGS.EXPLICIT_CONTEXT + context));
};

/**
 * Get ASN.1 Positive Integer raw byte array
 * @return {Uint8Array}
 */
Decoder.prototype.getAsn1PositiveInteger = function() {
  var data = this.getAsn1Integer();
  if (data[0] > 127) {
    throw new TypeError('Unexpected negative integer value');
  }
  while (!data[0]) {
    data = data.subarray(1);
  }
  return data;
};

/**
 * Get ASN.1 Bit String raw byte array
 * @param {boolean} unusedMustBeZero - true if the result must be byte aligned
 * @return {Uint8Array}
 */
Decoder.prototype.getAsn1BitString = function(unusedMustBeZero) {
  var raw = this._getBodyData(TAGS.BITSTRING);
  if (unusedMustBeZero) {
    if (raw[0] != 0) {
      throw new TypeError('Bitstring with unused bits not allowed');
    }
    raw = new Uint8Array(raw.subarray(1));
  }
  return raw;
};

/**
 * Get/Verify ASN.1 Null
 */
Decoder.prototype.getAsn1Null = function() {
  if (this._getBodyData(TAGS.NULL).length != 0) {
    throw new TypeError('Misformed ASN.1 NULL');
  }
};

/**
 * Get ASN.1 Sequence object
 * @return {Decoder}
 */
Decoder.prototype.getAsn1Sequence = function() {
  this._getBodyData(TAGS.SEQUENCE);
  return this;
};

/**
 * Get ASN.1 Set object
 * @return {Decoder}
 */
Decoder.prototype.getAsn1Set = function() {
  this._getBodyData(TAGS.SET);
  return this;
};

Decoder.prototype._getBodyData = function(tag) {
  if (tag != this.tag) {
    throw new TypeError('Tag mismatch, expected: ' + tag + ' got: ' + this.tag);
  }
  return this.body;
};

/**
 * Get the content part of the ASN.1 element
 * @return {Uint8Array}
 */
Decoder.prototype.getBodyData = function() {
  return this._getBodyData(this.tag);
};

/**
 * Get the tag of the ASN.1 element
 * @return {number}
 */
Decoder.prototype.getTag = function() {
  return this.tag;
};

/**
 * Get the entire ASN.1 element
 * @return {Uint8Array}
 */
Decoder.prototype.encode = function() {
  return new Uint8Array(this.rawDerString.subarray(0, this.body.length + this.startOfBody));
};

/**
 * Decode an outermost ASN.1 Sequence
 * @static
 * @param {(Buffer|Uint8Array)} rawDerString - DER binary
 * @return {Decoder}
 */
function decodeSequence(rawDerString) {
  var sequence = new Decoder(rawDerString, TAGS.SEQUENCE);
  if (sequence.body.length != (rawDerString.length - sequence.startOfBody)) {
    throw new TypeError('Sequence length error');
  }
  return sequence;
}

exports.Encoder = Encoder;
exports.Decoder = Decoder;
exports.TAGS = TAGS;
exports.decodeSequence = decodeSequence;
