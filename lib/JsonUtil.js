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
/*                             JsonUtil                           */
/*================================================================*/

// Classes for enabling strict(er) JSON processing

const Base64Url = require('./Base64Url');
const Big       = require('./contrib/big/Big');
const ByteArray = require('./ByteArray');
const DateTime  = require('./DateTime');
const Keys      = require('./Keys');
const Jef       = require('./Jef');
const Jcs       = require('./Jcs');
const Hex       = require('./Hex');

function getNormalizedData(object) {
  // Canonicalization anybody? Using ES6/V8 it JustWorks(tm) out of the box!
  return ByteArray.stringToUtf8(JSON.stringify(object));
}

const DECIMAL_PATTERN = new RegExp(/^(-?([1-9][0-9]*|0)[\.][0-9]+)$/);
const INTEGER_PATTERN = new RegExp(/^(-?[1-9][0-9]*|0)$/);

const MAX_SAFE_INTEGER = 9007199254740991;

function bigIntegerSyntax(string) {
  if (INTEGER_PATTERN.test(string)) {
    return string;
  }
  throw new TypeError('Not a big integer');
}

function bigDecimalSyntax(string, optionalDecimals) {
  if (INTEGER_PATTERN.test(string) || DECIMAL_PATTERN.test(string)) {
    if (optionalDecimals !== undefined) {
      if (string.indexOf('.') < 0 || string.indexOf('.') != string.length - optionalDecimals - 1) {
        throw new TypeError('Number doesn\'t have ' + optionalDecimals + ' decimals');
      }
    }
    return string;
  }
  throw new TypeError('Not a big decimal number');
}

function getBigString(value, optionalDecimals) {
  if (value instanceof Big) {
    return optionalDecimals === undefined ? value.toString() : value.toFixed(optionalDecimals);
  }
  throw new TypeError('Not "Big" type');
}

function getBigIntegerString(value) {
  return bigIntegerSyntax(getBigString(value));
}

function getBigDecimalString(value, optionalDecimals) {
  return bigDecimalSyntax(getBigString(value, optionalDecimals));
}

function getIntegerValue(value) {
  if (typeof value != 'number' || Math.abs(value) > MAX_SAFE_INTEGER || value.toString().indexOf('.') >= 0) {
    throw new TypeError('Bad integer: ' + value);
  }
  return value;
}

////////////////////////////////////////////////
// ObjectWriter
////////////////////////////////////////////////

function ObjectWriter(optionalObjectOrReader) {
  if (optionalObjectOrReader === undefined) {
    this.object = {};
  } else if (optionalObjectOrReader instanceof ObjectReader) {
    this.object = optionalObjectOrReader.object;
    if (this.object._isArray()) {
      throw new TypeError('You cannot update array objects');
    }
  } else if (typeof optionalObjectOrReader === 'object' && !Array.isArray(optionalObjectOrReader)) {
    this.object = optionalObjectOrReader;
  } else {
    throw new TypeError('Wrong init of ObjectWriter');
  }
}

ObjectWriter.prototype.getRootObject = function() {
  return this.object;
};

ObjectWriter.prototype._setProperty = function(name, value) {
  if (typeof name != 'string') {
    throw new TypeError('Undefined property for value: ' + value);
  }
  this.object[name] = value;
  return this;
};

ObjectWriter.prototype.setString = function(name, value) {
  if (typeof value != 'string') {
    throw new TypeError('Bad string: ' + name);
  }
  return this._setProperty(name, value);
};

ObjectWriter.prototype.setInt = function(name, value) {
  return this._setProperty(name, getIntegerValue(value));
};

ObjectWriter._doubleTest = function(value) {
  if (typeof value != 'number') {
    throw new TypeError('Bad float type: ' + (typeof value));
  }
  return value.toString();
};

ObjectWriter.prototype.setDouble = function(name, value) {
  return this._setProperty(name, ObjectWriter._doubleTest(value));
};

ObjectWriter.prototype.setBigInteger = function(name, value) {
  return this.setString(name, getBigIntegerString(value));
};

ObjectWriter.prototype.setBigDecimal = function(name, value, optionalDecimals) {
  return this.setString(name, getBigDecimalString(value, optionalDecimals));
};

ObjectWriter._boolTest = function(value) {
  if (typeof value != 'boolean') {
    throw new TypeError('Bad bool type: ' + (typeof value));
  }
  return value.toString();
};

ObjectWriter.prototype.setBoolean = function(name, value) {
  return this._setProperty(name, ObjectWriter._boolTest(value));
};

ObjectWriter.prototype.setNull = function(name) {
  return this._setProperty(name, null);
};

ObjectWriter.prototype.setDateTime = function(name, dateTime) {
  return this.setString(name, DateTime.toIsoTime(dateTime));
};

ObjectWriter.prototype.setBinary = function(name, value) {
  return this.setString(name, Base64Url.encode(value));
};

ObjectWriter.prototype.setDynamic = function(callback) {
  return callback(this);
};

ObjectWriter.setCorePublicKey = function(publicKey) {
  var writer = new ObjectWriter();
  if (publicKey instanceof Keys.PublicKey) {
    Object.keys(publicKey.jcs).forEach((key) => {
      writer._setProperty(key, publicKey.jcs[key]);
    });
    return writer;
  }
  throw new TypeError('Not "PublicKey"');
};

ObjectWriter.prototype.setPublicKey = function(publicKey) {
  return this.setObject(Jcs.PUBLIC_KEY_JSON, ObjectWriter.setCorePublicKey(publicKey));
};

ObjectWriter.prototype.setSignature = function(signer) {
  signer.sign(this.object);
  return this;
};

function _encodeEncryptedObject(unencryptedData,
                                dataEncryptionAlgorithm,
                                keyId,
                                keyEncryptionKey,
                                keyEncryptionAlgorithm,
                                dataEncryptionKey) {
  var encryptionObject = new ObjectWriter().setString(Jcs.ALGORITHM_JSON, dataEncryptionAlgorithm)
  if (keyEncryptionAlgorithm) {
    var encryptedKey = encryptionObject.setObject(Jef.ENCRYPTED_KEY_JSON)
      .setString(Jcs.ALGORITHM_JSON, keyEncryptionAlgorithm);
    encryptedKey.setPublicKey(keyEncryptionKey);
    if (Jef.isRsaAlgorithm(keyEncryptionAlgorithm)) {
      dataEncryptionKey = Jef.generateDataEncryptionKey(dataEncryptionAlgorithm);
      encryptedKey.setBinary(Jef.CIPHER_TEXT_JSON,
                             Jef.rsaEncryptKey(keyEncryptionAlgorithm,
                             dataEncryptionKey,
                             keyEncryptionKey));
    } else {
      var ecdhRes = Jef.senderKeyAgreement(keyEncryptionAlgorithm,
                                           dataEncryptionAlgorithm,
                                           keyEncryptionKey);
      dataEncryptionKey = ecdhRes.sharedSecret;
      encryptedKey.setObject(Jef.EPHEMERAL_KEY_JSON, ObjectWriter.setCorePublicKey(ecdhRes.publicKey));
    }
  } else {
    if (keyId) {
      encryptionObject.setString(Jcs.KEY_ID_JSON, keyId)
    }
  }
  var result = Jef.contentEncryption(dataEncryptionAlgorithm,
                                     dataEncryptionKey,
                                     unencryptedData,
                                     encryptionObject.getNormalizedData());
  return encryptionObject
    .setBinary(Jef.IV_JSON, result.iv)
    .setBinary(Jef.TAG_JSON, result.tag)
    .setBinary(Jef.CIPHER_TEXT_JSON, result.cipherText);
};

ObjectWriter.setAsymEncryptionObject = function(unencryptedData,
                                                dataEncryptionAlgorithm,
                                                keyEncryptionKey,
                                                keyEncryptionAlgorithm) {
  return _encodeEncryptedObject(unencryptedData,
                                dataEncryptionAlgorithm,
                                null,
                                keyEncryptionKey,
                                keyEncryptionAlgorithm,
                                null);
};

ObjectWriter.setSymEncryptionObject = function(unencryptedData,
                                               dataEncryptionAlgorithm,
                                               keyId,
                                               dataEncryptionKey) {
return _encodeEncryptedObject(unencryptedData,
                              dataEncryptionAlgorithm,
                              keyId,
                              null,
                              null,
                              dataEncryptionKey);
};

ObjectWriter.prototype.setObject = function(name, optionalReaderOrWriter) {
  if (optionalReaderOrWriter === undefined) {
    var writer = new ObjectWriter();
    this._setProperty(name, writer.object);
    return writer;
  }
  if (optionalReaderOrWriter instanceof ObjectReader ||
      optionalReaderOrWriter instanceof ObjectWriter) {
    return this._setProperty(name, optionalReaderOrWriter.object);
  }
  throw new TypeError('Unknown argument');
};

ObjectWriter.prototype.setArray = function(name, optionalWriter) {
  if (optionalWriter === undefined) {
    var writer = new ArrayWriter();
    this._setProperty(name, writer.array);
    return writer;
  }
  if (optionalWriter instanceof ArrayWriter) {
    return this._setProperty(name, optionalWriter.array);
  }
  throw new TypeError('"ArrayWriter" expected');
};

ObjectWriter.prototype.getNormalizedData = function() {
  return getNormalizedData(this.object);
};

ObjectWriter.prototype.toString = function(optionalFormat) {
  return prettyPrint(this.object, optionalFormat);
};


////////////////////////////////////////////////
// ArrayWriter
////////////////////////////////////////////////

function ArrayWriter() {
  this.array = [];
}

ArrayWriter.prototype._add = function(value) {
  this.array.push(value);
  return this;
};

ArrayWriter.prototype.setString = function(value) {
  if (typeof value != 'string') {
    throw new TypeError('Not a string');
  }
  return this._add(value);
};

ArrayWriter.prototype.setInt = function(value) {
  return this._add(getIntegerValue(value));
};

ArrayWriter.prototype.setBigInteger = function(value) {
  return this.setString(getBigIntegerString(value));
};

ArrayWriter.prototype.setBigDecimal = function(value, optionalDecimals) {
  return this.setString(getBigDecimalString(value, optionalDecimals));
};

ArrayWriter.prototype.setDouble = function(value) {
  return this._add(ObjectWriter._doubleTest(value));
};

ArrayWriter.prototype.setBoolean = function(value) {
  return this._add(ObjectWriter._boolTest(value));
};

ArrayWriter.prototype.setNull = function() {
  return this._add(null);
};

ArrayWriter.prototype.setBinary = function(value) {
  return this._add(Base64Url.encode(value));
};

ArrayWriter.prototype.setDateTime = function(dateTime) {
  return this.setString(DateTime.toIsoTime(dateTime));
};

ArrayWriter.prototype.setArray = function(optionalWriter) {
  if (optionalWriter === undefined) {
    var writer = new ArrayWriter();
    this._add(writer.array);
    return writer;
  }
  if (optionalWriter instanceof ArrayWriter) {
    return this._add(optionalWriter.array);
  }
  throw new TypeError('JSONArrayWriter expected');
};

ArrayWriter.prototype.setObject = function(optionalWriter) {
  if (optionalWriter === undefined) {
    var writer = new ObjectWriter();
    this._add(writer.object);
    return writer;
  }
  if (optionalWriter instanceof ObjectWriter) {
    return this._add(optionalWriter.object);
  }
  throw new TypeError('JSONObjectWriter expected');
};

ArrayWriter.prototype.toString = function(optionalFormat) {
  return prettyPrint(this.array, optionalFormat);
};


////////////////////////////////////////////////
// ObjectReader
////////////////////////////////////////////////

function ObjectReader(object, optionalProperty) {
  if (typeof object !== 'object' || Array.isArray(object)) {
    throw new TypeError('First argument must be an object');
  }
  if (optionalProperty !== undefined) {
    if (typeof optionalProperty != 'string') {
      throw new TypeError('Second argument must be a string');
    }
    object = object[optionalProperty];
    if (typeof object !== 'object' || Array.isArray(object)) {
      throw new TypeError('Second argument must point to an object');
    }
  }
  this.object = object;
  this.checker = {};
}

ObjectReader.prototype.getRootObject = function() {
  return this.object;
};

ObjectReader.parse = function(jsonString) {
  if (jsonString instanceof Buffer) {
    jsonString = jsonString.toString('utf8');
  } else if (jsonString instanceof Uint8Array) {
    jsonString = ByteArray.utf8ToString(jsonString);
  }
  if (typeof jsonString !== 'string') {
    throw new TypeError('Argument must be String, Buffer, or Uint8Array not:' + typeof jsonString);
  }
  return new ObjectReader(JSON.parse(jsonString));
};

ObjectReader.prototype._get = function(name) {
  if (typeof name !== 'string') {
    throw new TypeError('First argument must be a string');
  }
  var value = this.object[name];
  if (value === undefined) {
    throw new TypeError('Property "' + name + '" missing');
  }
  this.checker[name] = true;
  return value;
};

ObjectReader.prototype._getCnd = function(name, defaultValue) {
  if (typeof name !== 'string') {
    throw new TypeError('First argument must be a string');
  }
  var value = this.object[name];
  if (value === undefined) {
    return defaultValue;
  }
  this.checker[name] = true;
  return value;
};

ObjectReader.prototype.hasProperty = function (name) {
  if (typeof name !== 'string') {
    throw new TypeError('Argument must be a string');
  }
  return this.object[name] !== undefined;
};

ObjectReader.prototype.getString = function(name) {
  var value = this._get(name);
  if (typeof value !== 'string') {
    throw new TypeError('String value expected');
  }
  return value;
};
 
ObjectReader.prototype.getStringConditional = function(name, defaultValue) {
  var value = this._getCnd(name, defaultValue);
  if (value !== undefined && typeof value !== 'string') {
    throw new TypeError('String value expected');
  }
  return value;
};

ObjectReader.prototype.getInt = function(name) {
  return getIntegerValue(this._get(name));
};

ObjectReader.prototype.getBigInteger = function(name) {
  return new Big(bigIntegerSyntax(this.getString(name)));
};

ObjectReader.prototype.getBigDecimal = function(name, optionalDecimals) {
  return new Big(bigDecimalSyntax(this.getString(name), optionalDecimals));
};

ObjectReader.prototype.getBoolean = function(name) {
  var value = this._get(name);
  if (typeof value !== 'boolean') {
    throw new TypeError('Not a boolean: ' + name);
  }
  return value;
};

ObjectReader.prototype.getBooleanConditional = function(name, defaultValue) {
  if (defaultValue === undefined) {
    defaultValue = false;
  }
  var value = this._getCnd(name, defaultValue);
  if (typeof value !== 'boolean') {
    throw new TypeError('Boolean value expected');
  }
  return value;
};

ObjectReader.prototype.getBinary = function(name) {
  return Base64Url.decode(this.getString(name));
};

ObjectReader.prototype.isNull = function(name) {
  return this._get(name) === null;
};

ObjectReader.prototype.getArray = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || !Array.isArray(value) || value === null) {
    throw new TypeError('Not an array: ' + name);
  }
  return this.checker[name] = new ArrayReader(value);
};

ObjectReader.prototype.getDateTime = function(name) {
  return DateTime.parseIsoDateTime(this.getString(name));
};

ObjectReader.prototype._getObject = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || Array.isArray(value) || value === null) {
    throw new TypeError('Not an object: ' + name);
  }
  return value;
};

ObjectReader.prototype.getCorePublicKey = function() {
  return Keys._encodePublicKey(this);
};

ObjectReader.prototype.getPublicKey = function() {
  return this.getObject(Jcs.PUBLIC_KEY_JSON).getCorePublicKey();
};

ObjectReader.prototype.getSignature = function() {
  this._getObject(Jcs.SIGNATURE_JSON);
  return new Jcs.Verifier(true).decodeSignature(this.object);
};

ObjectReader.prototype.getEncryptionObject = function() {
  return new Jef.EncryptedData(this);
};

ObjectReader.prototype.getObject = function(name) {
  return this.checker[name] = new ObjectReader(this._getObject(name));
};

ObjectReader.prototype.scanItem = function(name) {
  var object = this._get(name);
  return this;
};

ObjectReader.prototype.getNormalizedData = function() {
  return getNormalizedData(this.object);
};

ObjectReader.prototype.checkForUnread = function() {
  Object.keys(this.object).forEach((entry) => {
    var object = this.checker[entry];
    if (object === undefined) {
      throw new TypeError('Property not read: ' + entry);
    }
    if (typeof object === 'object') {
      object.checkForUnread();
    }
  });
};

ObjectReader.prototype.toString = function(optionalFormat) {
  return prettyPrint(this.object, optionalFormat);
};

////////////////////////////////////////////////
// ArrayReader
////////////////////////////////////////////////

function ArrayReader(array) {
  if (typeof array !== 'object' || !Array.isArray(array)) {
    throw new TypeError('First argument must be an array');
  }
  this.array = array;
  this.checker = [];
}

ArrayReader.prototype._getValue = function() {
  if (this.checker.length == this.array.length) {
    throw new TypeError('Array index out of range: ' + this.checker.length);
  }
  return this.array[this.checker.length];
};

ArrayReader.prototype._readEntry = function() {
  var value = this._getValue();
  this.checker.push(true);
  return value;
};

ArrayReader.prototype.hasMore = function() {
  return this.checker.length < this.array.length;
};

ArrayReader.prototype.getString = function() {
  var value = this._readEntry();
  if (typeof value !== 'string') {
    throw new TypeError('String value expected');
  }
  return value;
};
 
ArrayReader.prototype.getBinary = function() {
  return Base64Url.decode(this.getString());
};

ArrayReader.prototype.getBigInteger = function() {
  return new Big(bigIntegerSyntax(this.getString()))
};

ArrayReader.prototype.getBigDecimal = function(optionalDecimals) {
  return new Big(bigDecimalSyntax(this.getString(), optionalDecimals))
};

ArrayReader.prototype.getInt = function() {
  return getIntegerValue(this._readEntry());
};

ArrayReader.prototype.getBoolean = function() {
  var value = this._readEntry();
  if (typeof value !== 'boolean') {
    throw new TypeError('Not a boolean');
  }
  return value;
};

ArrayReader.prototype.isNull = function() {
  return this._getValue() === null;
};

ArrayReader.prototype.getArray = function() {
  var value = this._getValue();
  if (typeof value !== 'object' || !Array.isArray(value) || value === null) {
    throw new TypeError('Not an array');
  }
  var arrayReader = new ArrayReader(value);
  this.checker.push(arrayReader);
  return arrayReader; 
};

ArrayReader.prototype.getObject = function(name) {
  var value = this._getValue();
  if (typeof value !== 'object' || Array.isArray(value) || value === null) {
    throw new TypeError('Not an object');
  }
  var objectReader = new ObjectReader(value);
  this.checker.push(objectReader);
  return objectReader;
};

ArrayReader.prototype.scanItem = function() {
  this._readEntry();
};

ArrayReader.prototype.checkForUnread = function() {
  if (this.checker.length < this.array.length) {
    throw new TypeError('All array items were not read');
  }
  this.checker.forEach((entry) => {
    if (typeof entry === 'object') {
      entry.checkForUnread();
    }
  });
};

ArrayReader.prototype.toString = function(optionalFormat) {
  return prettyPrint(this.array, optionalFormat);
};


////////////////////////////////////////////////
// Printer (local object only)
////////////////////////////////////////////////

const STANDARD_INDENT   = 2;
const HTML_INDENT       = 4;

const FORMAT_HTML       = 0;
const FORMAT_PRETTY     = 1;
const FORMAT_JAVASCRIPT = 2;

const HTML_VARIABLE_COLOR = '#008000';
const HTML_STRING_COLOR   = '#0000C0';
const HTML_PROPERTY_COLOR = '#C00000';
const HTML_KEYWORD_COLOR  = '#606060';

const JS_ID_PATTERN = new RegExp(/^[a-zA-Z$_]+[a-zA-Z$_0-9]*$/);

function JsType(object) {
  this.type = typeof object;
  this.object = false;
  this.array = false;
  this.complex = false;
  if (typeof object === 'object') {
    this.complex = true;
    if (Array.isArray(object)) {
      this.array = true;
      this.type = 'array';
    } else {
      this.object = true;
    }
  }
}

function htmlColorBegin(color) {
  return '<span style="color:' + color + '">';
}

function Printer(optionalFormat) {
  if (optionalFormat === undefined) {
    optionalFormat = FORMAT_PRETTY;
  }
  this.indentFactor = optionalFormat == FORMAT_HTML ? HTML_INDENT : STANDARD_INDENT;
  this.javaScriptMode = optionalFormat == FORMAT_JAVASCRIPT;
  this.htmlMode = optionalFormat == FORMAT_HTML;
}

Printer.prototype.newLine = function() {
  this.buffer += this.htmlMode ? '<br>' : '\n';
};

Printer.prototype.indentLine = function() {
  this.indent += this.indentFactor;
};

Printer.prototype.undentLine = function() {
  this.indent -= this.indentFactor;
};

Printer.prototype.printOneElement = function(jsonValue) {
  if (typeof jsonValue == 'object' && jsonValue !== null) {
    if (Array.isArray(jsonValue)) {
      this.printArray(jsonValue);
    } else {
      this.printObject(jsonValue);
    }
  } else {
    this.printSimpleValue(jsonValue, false);
  }
};

Printer.prototype.newUndentSpace = function() {
  this.newLine();
  this.undentLine();
  this.spaceOut();
};

Printer.prototype.newIndentSpace = function() {
  this.newLine();
  this.indentLine();
  this.spaceOut();
};

Printer.prototype.printObject = function(object) {
  this.buffer += '{';
  this.indentLine();
  var next = false;
  Object.keys(object).forEach((property) => {
    var value = object[property];
    if (next) {
      this.buffer += ',';
    }
    this.newLine();
    next = true;
    this.printProperty(property);
    this.printOneElement(value);
  });
  this.newUndentSpace();
  this.buffer += '}';
};

Printer.prototype.printArray = function(array) {
  this.buffer += '[';
  if (array.length > 0) {
    var mixed = false;
    var firstType = new JsType(array[0]);
    for (var q = 0; q < array.length; q++) {
      var nextType = new JsType(array[q]);
      if (firstType.complex != nextType.complex ||
       (firstType.complex && firstType.type != nextType.type)) {
        mixed = true;
        break;
      }
    }
    if (mixed ||(array.length == 1 && firstType.object)) {
      var next = false;
      for (var q = 0; q < array.length; q++) {
        if (next) {
          this.buffer += ',';
        } else {
          next = true;
        }
        this.printOneElement(array[q]);
      }
    } else if (firstType.object) {
      this.printArrayObjects(array);
    } else if (firstType.array) {
      this.newIndentSpace();
      var next = false;
      for (var q = 0; q < array.length; q++) {
        var subArray = array[q];
        if (next) {
          this.buffer += ',';
        } else {
          next = true;
        }
        this.printArray(subArray);
      }
      this.newUndentSpace();
    } else {
      this.printArraySimple(array);
    }
  }
  this.buffer += ']';
};

Printer.prototype.printArraySimple = function(array) {
  var i = 0;
  for (var q = 0; q < array.length; q++) {
    i += array[q].toString().length;
  }
  var brokenLines = i > 100;
  var next = false;
  if (brokenLines) {
    this.indentLine();
    this.newLine();
  }
  for (var q = 0; q < array.length; q++) {
    if (next) {
      this.buffer += ',';
      if (brokenLines) {
        this.newLine();
      }
    }
    if (brokenLines) {
      this.spaceOut();
    }
    this.printSimpleValue(array[q], false);
    next = true;
  }
  if (brokenLines) {
    this.newUndentSpace();
  }
};

Printer.prototype.printArrayObjects = function(array) {
  this.newIndentSpace();
  var next = false;
  for (var q = 0; q < array.length; q++) {
    if (next) {
      this.buffer += ',';
      this.newLine();
      this.spaceOut();
    }
    this.printObject(array[q]);
    next = true;
  }
  this.newUndentSpace();
};

Printer.prototype.printSimpleValue = function(value, property) {
  var string = value === null ? "null" : value.toString();
  if (typeof value != 'string') {
    if (this.htmlMode) {
      this.buffer += htmlColorBegin(HTML_VARIABLE_COLOR);
    }
    this.buffer += string;
    if (this.htmlMode) {
      this.buffer += '</span>';
    }
    return;
  }
  var quoted = !property || !this.javaScriptMode || !JS_ID_PATTERN.test(string);
  if (this.htmlMode) {
    this.buffer += '&quot;' + htmlColorBegin(property ?
       string.startsWith('@') ? HTML_KEYWORD_COLOR : HTML_PROPERTY_COLOR : HTML_STRING_COLOR);
  } else if (quoted) {
    this.buffer += '"';
  }
  for (var i = 0; i < string.length; i++) {
    var c = string.charAt(i);
    if (this.htmlMode) {
      switch (c) {
/* 
  HTML needs specific escapes...
*/
        case '<':
          this.buffer += '&lt;';
          continue;
    
        case '>':
          this.buffer += '&gt;';
          continue;
    
        case '&':
          this.buffer += '&amp;';
          continue;
    
        case '"':
          this.buffer += '\\&quot;';
          continue;
      }
    }

    switch (c) {
      case '\\':
      case '"':
        this.escapeString(c);
        break;
  
      case '\b':
        this.escapeString('b');
        break;
  
      case '\f':
        this.escapeString('f');
        break;
  
      case '\n':
        this.escapeString('n');
        break;
  
      case '\r':
        this.escapeString('r');
        break;
  
      case '\t':
        this.escapeString('t');
        break;
  
      case '&':
        if (this.javaScriptMode) {
          this.escapeString('u0026');
          break;
        }
  
      case '>':
        if (this.javaScriptMode) {
          this.escapeString('u003e');
          break;
        }
  
      case '<':
        if (this.javaScriptMode) {
          this.escapeString('u003c');
          break;
        }
  
      default:
        var utfValue = c.charCodeAt(0);
        if (utfValue < 0x20) {
          this.escapeString('u' + Hex.fourHex(utfValue));
          break;
        }
        this.buffer += c;
    }
  }
  if (this.htmlMode) {
    this.buffer += '</span>&quot;';
  } else if (quoted) {
    this.buffer += '"';
  }
};

Printer.prototype.escapeString = function(c) {
  this.buffer += '\\' + c;
};

Printer.prototype.singleSpace = function() {
  this.buffer += this.htmlMode ? '&nbsp;' : ' ';
};

Printer.prototype.printProperty = function(name) {
  this.spaceOut();
  this.printSimpleValue(name, true);
  this.buffer += ':';
  this.singleSpace();
};

Printer.prototype.spaceOut = function() {
  for (var i = 0; i < this.indent; i++) {
    this.singleSpace();
  }
};

Printer.prototype.print = function(object) {
  this.buffer = '';
  this.indent = 0;
  if (typeof object == 'object') {
    if (Array.isArray(object)) {
      this.printArray(object);
    } else {
      this.printObject(object);
    }
  } else {
    throw new TypeError('Only arrays and objects are supported by "prettyPrint"');
  }
  if (!this.javaScriptMode) {
    this.newLine();
  }
  return this.buffer;
};

function prettyPrint(object, optionalFormat) {
  return new Printer(optionalFormat).print(object);
}


exports.ObjectReader = ObjectReader;
exports.ObjectWriter = ObjectWriter;
exports.ArrayReader  = ArrayReader;
exports.ArrayWriter  = ArrayWriter;

exports.getNormalizedData = getNormalizedData;

exports.prettyPrint       = prettyPrint;
exports.FORMAT_HTML       = FORMAT_HTML;
exports.FORMAT_PRETTY     = FORMAT_PRETTY;
exports.FORMAT_JAVASCRIPT = FORMAT_JAVASCRIPT;
