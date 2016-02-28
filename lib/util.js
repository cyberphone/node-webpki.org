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
/*                             Util                               */
/*================================================================*/

// Various methods that may be useful

const Util = {

  getPropertyUnconditionally: function (o, name) {
    var value = o[name];
    if (value === undefined) {
      throw new TypeError('Property "' + name + '" missing');
    }
    return value;
  },
  
  getStringUnconditionally: function(o, name) {
    var value = Util.getPropertyUnconditionally(o, name);
    if (typeof value !== 'string') {
      throw new TypeError('Property "' + name + '" must be a string');
    }
    return value;
  },

  getObjectUnconditionally: function(o, name) {
    var value = Util.getPropertyUnconditionally(o, name);
    if (typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError('Property "' + name + '" must be an "Object"');
    }
    return value;
  },

  getArrayUnconditionally: function(o, name) {
    var value = Util.getPropertyUnconditionally(o, name);
    if (!Array.isArray(value)) {
      throw new TypeError('Property "' + name + '" must be an array[]');
    }
    return value;
  },

  checkForUnexpected: function (o, expected) {
    for (var key in o) {
      expected--;
    }
    if (expected) {
      throw new TypeError('Object contains alien or unread properties: ' + Object.keys(o));
    }
  }

};

module.exports = Util;
