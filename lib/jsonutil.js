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

// A class for enabling strict(er) JSON processing

const Base64Url = require('./base64url');
const BigInteger = require('./biginteger');
const DateTime = require('./datetime');

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
  return BigInteger.BigInteger.fromString(this.getString(name));
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
  return value;
};

ObjectReader.prototype.getArrayReader = function(name) {
  return this.checker[name] = new ArrayReader(this.getArray(name));
};

ObjectReader.prototype.getDateTime = function(name) {
  return DateTime.parseIsoDateTime(this.getString(name));
};

ObjectReader.prototype.getObject = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Not an object: ' + name);
  }
  return value;
};

ObjectReader.prototype.getObjectReader = function(name) {
  return this.checker[name] = new ObjectReader(this.getObject(name));
};

ObjectReader.prototype.scanItem = function(name) {
  this._get(name);
  return this;
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
  return value;
};

ArrayReader.prototype.getArrayReader = function() {
  return this.checker[this.checker.length] = new ArrayReader(this.getArray());
};

ArrayReader.prototype.getObject = function() {
  var value = this._get();
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Not an object');
  }
  return value;
};

ArrayReader.prototype.getObjectReader = function(name) {
  return this.checker[this.checker.length] = new ObjectReader(this.getObject());
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

const JsonUtil = {
  ObjectReader: ObjectReader,
  ArrayReader : ArrayReader
};

module.exports = JsonUtil;
