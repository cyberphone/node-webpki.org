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
 
 var ByteArray = require('./bytearray');
 
/*================================================================*/
/*                            ASN1                                */
/*================================================================*/

// Ultra-light ASN.1 library in JavaScript

const TAGS = {
    OID                : 0x06,
    SEQUENCE           : 0x30,
    SET                : 0x31,
    INTEGER            : 0x02,
    NULL               : 0x05,
    BITSTRING          : 0x03,
    UTF8STRING         : 0x0C,
    BMPSTRING          : 0x1E,
    EXPLICIT_CONTEXT   : 0xA0,
    OCTET_STRING       : 0x04
};

const LIBRARY_LIMIT = 50000;  // 50k of ASN.1 is all we care of

function _lengthCheck(length) {
  if (length > LIBRARY_LIMIT) {
    throw new TypeError('Exceeded library limit ' + LIBRARY_LIMIT + ' bytes');
  }
}

function Encoder(tag, argument) {
  this.components = [];  /* Encoder or Uint8Array */
  this.components.push(argument);
  this.tag = tag;
  return this;
}

Encoder.prototype.addComponent = function(component) {
  this.components.push(component);
  return this;
};

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
  return this.encoded = ByteArray.add (this.encoded, array);
};

function Decoder(rawDerString) {
  _lengthCheck (rawDerString.length);
  this.rawDerString = rawDerString;
  this.position = 0;
  this.tag = this._readDERByte();
  var length = this._readDERByte();
  if ((length & 0x80) != 0) {
    var bytes = length & 0x7F;
    length = 0;
    while (bytes-- > 0) {
      length <<= 8;
      length += this._readDERByte();
      _lengthCheck(length);
    }
  }
  this.start_of_body = this.position;
  this.body = new Uint8Array (length);
  for (var i = 0; i < length; i++) {
    this.body[i] = this._readDERByte(); 
  }
  if (this.tag == TAGS.SEQUENCE || this.tag == TAGS.SET) {
    this.components = [];
    var newDerString = this.body;
    while (newDerString.length != 0) {
      var asn1_object = new Decoder(newDerString);
      var chunk = asn1_object.body.length + asn1_object.start_of_body; 
      this.components.push (asn1_object);
      if (chunk > newDerString.length) {
        throw new TypeError('Length error for tag: ' + asn1_object.tag);
      }
      newDerString = new Uint8Array(newDerString.subarray(chunk));
    }
  } else if (length == 0 && this.tag != TAGS.NULL) {
    throw new TypeError('Zero-length body not permitted for tag: ' + this.tag);
  }
  return this;
}

Decoder.prototype._readDERByte = function() {
  if (this.position >= this.rawDerString.length) {
    throw new TypeError('Buffer underrun for tag: ' + this.tag);
  }
  return this.rawDerString[this.position++];
};

Decoder.prototype.numberOfComponents = function() {
  if (this.components === undefined) {
    throw new TypeError('This object type doesn\'t have components: ' + this.tag);
  }
  return this.components.length;
};

Decoder.prototype.getComponent = function(index) {
  if (index >= this.numberOfComponents ()) {
    throw new TypeError('Component index out of range: ' + index);
  }
  return this.components[index];
};

Decoder.prototype.getASN1ObjectIDRawData = function() {
  return this._getBodyData(TAGS.OID);
};

Decoder.prototype.getASN1Integer = function() {
  return this._getBodyData(TAGS.INTEGER);
};

Decoder.prototype.getASN1OctetString = function() {
  return this._getBodyData(TAGS.OCTET_STRING);
};

Decoder.prototype.getASN1ExplicitContext = function(context) {
  return new Decoder(this._getBodyData(TAGS.EXPLICIT_CONTEXT + context));
};

Decoder.prototype.getASN1PositiveInteger = function() {
  var data = this.getASN1Integer();
  if (data[0] > 127) {
    throw new TypeError('Unexpected negative integer value');
  }
  while (!data[0]) {
    data = data.subarray(1);
  }
  return data;
};

Decoder.prototype.getASN1BitString = function(unused_must_be_zero) {
  var raw = this._getBodyData(TAGS.BITSTRING);
  if (unused_must_be_zero) {
    if (raw[0] != 0) {
      throw new TypeError('Bitstring with unused bits not allowed');
    }
    raw = new Uint8Array(raw.subarray(1));
  }
  return raw;
};

Decoder.prototype.getASN1NULL = function() {
  if (this._getBodyData(TAGS.NULL).length != 0) {
    throw new TypeError('Misformed ASN.1 NULL');
  }
};

Decoder.prototype.getASN1Sequence = function() {
  this._getBodyData(TAGS.SEQUENCE);
  return this;
};

Decoder.prototype.getASN1Set = function() {
  this._getBodyData(TAGS.SET);
  return this;
};

Decoder.prototype._getBodyData = function(tag) {
  if (tag != this.tag) {
    throw new TypeError('Tag mismatch, expected: ' + tag + ' got: ' + this.tag);
  }
  return this.body;
};

Decoder.prototype.getBodyData = function() {
  return this._getBodyData(this.tag);
};

Decoder.prototype.getTag = function() {
  return this.tag;
};

Decoder.prototype.encode = function() {
  return new Uint8Array(this.rawDerString.subarray(0, this.body.length + this.start_of_body));
};

function decodeSequence(rawDerString) {
  var sequence = new Decoder (rawDerString, TAGS.SEQUENCE);
  if (sequence.body.length != (rawDerString.length - sequence.start_of_body)) {
    throw new TypeError('Sequence length error');
  }
  return sequence;
}

exports.Encoder = Encoder;
exports.Decoder = Decoder;
exports.TAGS = TAGS;
exports.decodeSequence = decodeSequence;


