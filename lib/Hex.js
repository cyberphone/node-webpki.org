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
/*                              Hex                               */
/*================================================================*/

// Just to avoid duplication all over the place

const Hex = {

  oneHex: function(value) {
    if (value < 10) {
      return String.fromCharCode(value + 48);
    }
    return String.fromCharCode(value + 87);
  },

  twoHex: function(value) {
    return Hex.oneHex(value >>> 4) + Hex.oneHex(value & 0xF);
  },

  fourHex: function(value) {
    return Hex.twoHex(value >>> 8) + Hex.twoHex(value & 0xFF);
  },
  
  dumpHex: function(blob) {
    var result = '';
    for (var i = 0; i < blob.length; i++) {
      result += Hex.twoHex(blob[i]);
    }
    return result;
  }

};

module.exports = Hex;
