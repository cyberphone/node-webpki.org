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
/*                           Base64URL                            */
/*================================================================*/

// Base64URL back and forth

const VALID = new RegExp('^[a-z,A-Z,0-9,\\-,_]*$');

const Base64URL = {

  decode: function(base64UrlString) {
    // Regular Base64 is more permissive than our take on Base64URL
    if (!VALID.test(base64UrlString)) {
      throw new TypeError('Bad Base64URL: ' + base64UrlString); 
    }
    // Note: We do not need to add padding because it is actually redundant
    var binaryData = new Buffer(base64UrlString.replace(/\-/g,'+').replace(/_/g,'/'), 'base64');
    // The built-in Base64 decoder seems to be a bit sloppy...
    if (Base64URL.encode(binaryData) != base64UrlString) {
      throw new TypeError('Inconsistent Base64URL: ' + base64UrlString);
    }
    return binaryData;
  },

  encode: function(binaryData) {
    return new Buffer(binaryData).toString('base64')
      .replace(/\+/g,'-')
      .replace(/\//g,'_')
      .replace(/=/g,'');
  }

};

module.exports = Base64URL;
