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
/*                             JsonUtil                           */
/*================================================================*/

// Classes for enabling strict(er) JSON processing

const Base64Url = require('./Base64Url');
const Big = require('./contrib/big/big');
const ByteArray = require('./ByteArray');
const DateTime = require('./DateTime');
const Keys = require('./Keys');
const Jcs = require('./Jcs');

function getNormalizedData(object) {
  // Canonicalization anybody? Using ES6/V8 it JustWorks(tm) out of the box!
  return ByteArray.stringToUtf8(JSON.stringify(object));
}

const DECIMAL_PATTERN = new RegExp(/^(-?([1-9][0-9]*|0)[\.][0-9]+)$/);
const INTEGER_PATTERN = new RegExp(/^(-?[1-9][0-9]*|0)$/);

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
  this.object[name] = value;
  return this;
};

ObjectWriter.prototype.setString = function(name, value) {
  if (typeof value != 'string') {
    throw new TypeError('Bad string: ' + name);
  }
  return this._setProperty(name, value);
};

ObjectWriter._intTest = function(value) {
  var intString = value.toString();
  if (typeof value != 'number' || intString.indexOf('.') >= 0) {
    throw new TypeError('Bad integer: ' + intString);
  }
  return value;
};

ObjectWriter.prototype.setInt = function(name, value) {
  return this._setProperty(name, ObjectWriter._intTest(value));
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

ObjectWriter.prototype.setPublicKey = function(publicKey) {
  if (publicKey instanceof Keys.PublicKey) {
    return this._setProperty(Jcs.PUBLIC_KEY_JSON, publicKey.jcs);
  }
  throw new TypeError('Not "PublicKey"');
};

ObjectWriter.prototype.setSignature = function(signer) {
  signer.sign(this.object);
  return this;
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
  return this._add(ObjectWriter._intTest(value));
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
  var value = this._get(name);
  if (typeof value !== 'number') {
    throw new TypeError('Not a number: ' + name);
  }
  return value;
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

ObjectReader.prototype.getBinary = function(name) {
  return Base64Url.decode(this.getString(name));
};

ObjectReader.prototype.getArray = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || !Array.isArray(value)) {
    throw new TypeError('Not an array: ' + name);
  }
  return this.checker[name] = new ArrayReader(value);
};

ObjectReader.prototype.getDateTime = function(name) {
  return DateTime.parseIsoDateTime(this.getString(name));
};

ObjectReader.prototype._getObject = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Not an object: ' + name);
  }
  return value;
};

ObjectReader.prototype.getPublicKey = function() {
  return Keys.encodePublicKey(this._getObject(Jcs.PUBLIC_KEY_JSON));
};

ObjectReader.prototype.getSignature = function() {
  this._getObject(Jcs.SIGNATURE_JSON);
  return new Jcs.Verifier(true).decodeSignature(this.object);
};

ObjectReader.prototype.getObject = function(name) {
  return this.checker[name] = new ObjectReader(this._getObject(name));
};

ObjectReader.prototype.scanItem = function(name) {
  this._get(name);
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

ArrayReader.prototype._get = function() {
  if (this.checker.length == this.array.length) {
    throw new TypeError('Array index out of range: ' + this.checker.length);
  }
  var value = this.array[this.checker.length];
  this.checker.push(true);
  return value;
};

ArrayReader.prototype.hasMore = function() {
  return this.checker.length < this.array.length;
};

ArrayReader.prototype.getString = function() {
  var value = this._get();
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
  var value = this._get();
  if (typeof value !== 'number') {
    throw new TypeError('Not a number');
  }
  return value;
};

ArrayReader.prototype.getBoolean = function() {
  var value = this._get();
  if (typeof value !== 'boolean') {
    throw new TypeError('Not a boolean');
  }
  return value;
};

ArrayReader.prototype.getArray = function() {
  var value = this._get();
  if (typeof value !== 'object' || !Array.isArray(value)) {
    throw new TypeError('Not an array');
  }
  return this.checker[this.checker.length] = new ArrayReader(value);
};

ArrayReader.prototype.getObject = function(name) {
  var value = this._get();
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Not an object');
  }
  return this.checker[this.checker.length] = new ObjectReader(value);
};

ArrayReader.prototype.scanItem = function() {
  this._get();
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


exports.ObjectReader = ObjectReader;
exports.ObjectWriter = ObjectWriter;
exports.ArrayReader  = ArrayReader;
exports.ArrayWriter  = ArrayWriter;
exports.getNormalizedData = getNormalizedData;
