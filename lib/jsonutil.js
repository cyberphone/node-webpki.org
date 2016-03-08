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

// A class for enabling strict JSON processing

const Base64Url = require('./base64url');

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
}

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

ObjectReader.prototype.getBinary = function(name) {
  return Base64Url.decode(this.getString(name));
};

ObjectReader.prototype.getInteger = function(name) {
  var value = this._get(name);
  if (typeof value !== 'number') {
    throw new TypeError('Not a number: ' + name);
  }
  return value;
};

ObjectReader.prototype.getBoolean = function(name) {
  var value = this._get(name);
  if (typeof value !== 'boolean') {
    throw new TypeError('Not a boolean: ' + name);
  }
  return value;
};

ObjectReader.prototype.getArray = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || !Array.isArray(value)) {
    throw new TypeError('Not an array: ' + name);
  }
  return value;
};

ObjectReader.prototype.getObject = function(name) {
  var value = this._get(name);
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Not an object: ' + name);
  }
  return value;
};

ObjectReader.prototype.checkForUnread = function() {
  Object.keys(this.object).forEach((entry) => {
    if (!(entry in this.checker)) {
      throw new TypeError('Property not read: ' + entry);
    }
  });
};

const JsonUtil = {
  Reader : ObjectReader
};

module.exports = JsonUtil;
