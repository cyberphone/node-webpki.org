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
/*                            ByteArray                           */
/*================================================================*/

/** Core methods for dealing with Uint8Array/Buffer
 * @module ByteArray
 */

const Hex = require('./Hex');

/**
 * @class
 */
const ByteArray = {

  /**
    * Test for equality
    * @param {(Uint8Aarray|Buffer)} arg1 - Argument 1
    * @param {(Uint8Aarray|Buffer)} arg2 - Argument 2
    * @return {boolean}
    */
  equals : function(arg1, arg2) {
    if (arg1.length != arg2.length) {
      return false;
    }
    for (var i = 0; i < arg1.length; i++) {
      if (arg1[i] != arg2[i]) {
        return false;
      }
    }
    return true;
  },

  /**
   * Convert string to UTF8
   * @param {string} string - String to be converted
   * @return {Uint8Array}
   */
  stringToUtf8 : function(string) {
    return new Uint8Array(Buffer.from(string, 'utf8'));
  },

  /**
   * Convert UTF8 to string
   * @param {(Uint8Aarray|Buffer)} byteArray - UTF8 array to be converted
   * @return {string}
   */
  utf8ToString : function(byteArray) {
    return Buffer.from(byteArray).toString('utf8');
  },

  /**
   * Add two arrays
   * @param {(Uint8Aarray|Buffer)} arg1 - Argument 1
   * @param {(Uint8Aarray|Buffer)} arg2 - Argument 2
   * @return {Uint8Aarray}
   */
  add : function(arg1, arg2) {
    var combined = new Uint8Array(arg1.length + arg2.length);
    var i = 0;
    while (i < arg1.length) {
      combined[i] = arg1[i++];
    }
    for (var j = 0; j < arg2.length; j++) {
      combined[i++] = arg2[j];
    }
    return combined;
  },

  /**
   * Convert to hex string
   * @param {(Uint8Aarray|Buffer)} arg - Argument
   * @return {string}
   */
  toHex : function(arg) {
    var result = '';
    for (var i = 0; i < arg.length; i++) {
      result += Hex.twoHex(arg[i]);
    }
    return result;
  }

};

module.exports = ByteArray;
