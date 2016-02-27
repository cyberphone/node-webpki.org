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
/*                            ByteArray                           */
/*================================================================*/

// A set of basic methods for dealing with Uint8Arrays.

const Hex = require('./hex');
 
const ByteArray = {

  equals: function(arg1, arg2) {
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

  stringToUTF8: function(string) {
    var buffer = [];
    for (var n = 0; n < string.length; n++) {
      var c = string.charCodeAt(n);
      if (c < 128) {
        buffer.push(c);
      } else if ((c > 127) && (c < 2048)) {
        buffer.push((c >> 6) | 0xC0);
        buffer.push((c & 0x3F) | 0x80);
      } else {
        buffer.push((c >> 12) | 0xE0);
        buffer.push(((c >> 6) & 0x3F) | 0x80);
        buffer.push((c & 0x3F) | 0x80);
      }
    }
    return new Uint8Array(buffer);
  },

  add: function(arg1, arg2) {
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

  toHex: function(arg) {
    var result = '';
    for (var i = 0; i < arg.length; i++) {
      result += Hex.twoHex(arg[i]);
    }
    return result;
  }

};

module.exports = ByteArray;
