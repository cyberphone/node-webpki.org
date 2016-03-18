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
/*                           BigInteger                           */
/*================================================================*/

// The JS version of BigInteger is just a thin wrapper over an "Uint8Array" and the only
// functionality offered beyond parsing and toString are tests for equivalence and zero.
// It is anticipated that all cryptographic functions are performed in other and lower
// layers of the platform.  Only positive values (and zero) are currently supported.

const ByteArray = require('./bytearray');

function BigInteger(optionalValue) {
  if (optionalValue === undefined) {
    this.value = null;
  } else {
    this.value = optionalValue;
    this._trim ();
  }
}

BigInteger.prototype._trim = function () {
  var offset = 0;
  while (this.value[offset] == 0 && offset < (this.value.length - 1)) {
    offset++;
  }
  if (offset != 0) {
    var trimmed = new Uint8Array(this.value.length - offset);
    for (var q = 0; q < trimmed.length; q++) {
      trimmed[q] = this.value[q + offset];
    }
    this.value = trimmed;
  }
};

BigInteger._base = function(optional_10_or_16_base) {
  if (optional_10_or_16_base === undefined) {
    return 10;
  }
  if (optional_10_or_16_base == 10) {
    return 10;
  }
  if (optional_10_or_16_base == 16) {
    return 16;
  }
  throw new TypeError('Incorrect base argument, only 10 and 16 are supported');
};

BigInteger._isZero = function(byteArray) {
  for (var i = 0; i < byteArray.length; i++) {
    if (byteArray[i] != 0) {
      return false;
    }
  }
  return true;
};

BigInteger.prototype.isZero = function() {
  return BigInteger._isZero(this.value);
};

BigInteger.prototype.getLong = function() {
  if (this.value.length > 8) {
    throw new TypeError('Out of "Long" range');
  }
  return this;
};

BigInteger._setSmallValue = function(byteArray, value) {
  var i = byteArray.length;
  byteArray[--i] = value;
  while (--i >= 0) {
    byteArray[i] = 0;
  }
};

BigInteger._getNextDigit = function(dividend, divisor) {
  var remainder = 0;
  for (var i = 0; i < dividend.length; i++) {
    remainder = dividend[i] |(remainder << 8);
    dividend[i] = Math.floor(remainder / divisor);
    remainder = Math.floor(remainder % divisor);
  }
  return remainder;
};

BigInteger.fromString = function(string, optional_10_or_16_base) {
  var base = BigInteger._base(optional_10_or_16_base);
  if (typeof string  == 'number') {
    string = string.toString();
  } else if (typeof string  != 'string') {
    throw new TypeError('Expected a string argument');
  }
  if (string.length == 0) {
    throw new TypeError('Empty string not allowed');
  }
  var bi = new BigInteger();
  var result = [];
  result[0] = 0;
  for (var i = 0; i < string.length; i++) {
    var n;
    var c = string.charAt(i);
    if (c >= '0' && c <= '9') {
      n = c.charCodeAt(0) - 48;
    } else if (base == 10) {
      throw new TypeError('Decimal number expected');
    } else if (c >= 'a' && c <= 'f') {
      n = c.charCodeAt(0) - 87;
    } else if (c >= 'A' && c <= 'F') {
      n = c.charCodeAt(0) - 55;
    } else {
      throw new TypeError('Hexadecimal number expected');
    }
    var carry = 0;
    var j = 0;
    while (j < result.length) {
      var bigres = base * result[j] + n + carry;
      n = 0;
      bigres -= (carry = Math.floor(bigres / 256)) * 256;
      result[j++] = bigres;
      if (carry > 0 && j == result.length) {
        result[j] = 0;
      }
    }
  }
  bi.value = new Uint8Array(result.length);
  for (var i = 0; i < result.length; i++) {
    bi.value [result.length - i - 1] = result[i];
  }
  bi._trim();
  return bi;
};

BigInteger.prototype.getByteArray = function() {
  if (!this.value) {
    throw new TypeError('BigInteger not initialized');
  }
  return this.value;
};

BigInteger.prototype.equals = function(bigInteger) {
  return ByteArray.equals(this.getByteArray(), bigInteger.getByteArray());
};

BigInteger.prototype.toString = function(optional_10_or_16_base) {
  var base = BigInteger._base(optional_10_or_16_base);
  var reversed_string = '';
  var divisor = new Uint8Array(this.getByteArray());
  do {
    var digit = BigInteger._getNextDigit(divisor, base);
    reversed_string += String.fromCharCode(digit + (digit > 9 ? 55 : 48));
  } while (!BigInteger._isZero(divisor));
  
  var result = '';
  var i = reversed_string.length;
  while (--i >= 0) {
    result += reversed_string.charAt(i);
  }
  return result;
};

exports.BigInteger = BigInteger;
