/*
 *  Copyright 2006-2017 WebPKI.org (http://webpki.org).
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
/*                            DateTime                            */
/*================================================================*/

// A set of basic methods for dealing with ISO date time.
// Always: YYYY-MM-DDThh:mm:ss
// Optionally: a '.' followed by 1-3 digits giving millisecond
// Finally: 'Z' for UTC or an UTC time-zone difference expressed as +hh:mm or -hh:mm

const DATE_PATTERN = new RegExp(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?([+-]\d{2}:\d{2}|Z)$/);

const DateTime = {

  parseIsoDateTime: function(dateTimeString) {
    if (DATE_PATTERN.test(dateTimeString)) {
      return new Date(dateTimeString);
    }
    throw new TypeError('Bad "Date" format: ' + dateTimeString); 
  },

  toIsoTime: function(date) {
    var dateTimeString = date.toISOString();
    DateTime.parseIsoDateTime(dateTimeString);
    var point = dateTimeString.indexOf('.');
    if (point > 0) {
      var end = dateTimeString.indexOf('Z');
      if (end < 0) {
        throw new TypeError('Bad "Date" format: ' + dateTimeString); 
      }
      return dateTimeString.substring(0, point) + dateTimeString.substring(end);
    }
    return dateTimeString;
  },
  
  now: function() {
    return DateTime.toIsoTime(new Date());
  },

  userTime: function() {
    var now = new Date();
    return DateTime.toIsoTime(new Date(now.getTime() - now.getTimezoneOffset() * 60 * 1000))
      .replace(/T/g,' ').replace(/Z/g,'');
  }
 
};

module.exports = DateTime;
