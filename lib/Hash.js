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
/*                              Hash                              */
/*================================================================*/

// Class for performing Hash operations

const Crypto = require('crypto');

const JsonUtil = require('./JsonUtil');

const ALGORITHMS = ['SHA256', 'SHA384', 'SHA512'];

const Hash = {

  hashBinary: function(hashAlgorithm, binaryData) {
    for (var q = 0; q < ALGORITHMS.length; q++) {
      if (ALGORITHMS[q] == hashAlgorithm) {
        var hash = Crypto.createHash(hashAlgorithm);
        hash.update(binaryData);
        return new Uint8Array(hash.digest());  
      }                
    }
    throw new TypeError('Unknown hash algorithm: ' + hashAlgorithm);
  },
               
  hashObject: function(hashAlgorithm, jsObjectOrReaderWriter) {
    return Hash.hashBinary(hashAlgorithm, 
                           JsonUtil.getCanonicalizedData(
                              JsonUtil.cleanObject(jsObjectOrReaderWriter)));
  }

};

module.exports = Hash;
