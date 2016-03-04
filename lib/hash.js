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
/*                              Hash                              */
/*================================================================*/

// Class for performing Hash operations

const Crypto = require('crypto');

const ByteArray = require('./bytearray');

const ALGORITHMS = ['SHA256', 'SHA384', 'SHA512'];

const Hash = {

  hashBinary: function (hashAlgorithm, binaryData) {
    for (var q = 0; q < ALGORITHMS.length; q++) {
      if (ALGORITHMS[q] == hashAlgorithm) {
        var hash = Crypto.createHash(hashAlgorithm);
        hash.update(binaryData);
        return new Uint8Array(hash.digest());  
      }                
    }
    throw new TypeError('Algorithm must be one of: ' + ALGORITHMS);
  },
              
  hashObject: function (hashAlgorithm, javaScriptObject) {
    return Hash.hashBinary(hashAlgorithm, ByteArray.stringToUTF8(JSON.stringify(javaScriptObject)));
  }

};

module.exports = Hash;
