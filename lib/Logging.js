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
/*                             Logging                            */
/*================================================================*/

// A very rudimentary logging facility

const DateTime = require('./DateTime');

function Logger(applicationName) {
  this.applicationName = applicationName;
}

Logger.prototype._createLine = function(type, message) {
  return DateTime.userTime() + ' ' + type + ' [' + this.applicationName + '] ' + message;
}; 

Logger.prototype.info = function(message) {
  console.log(this._createLine('INFO', message));
};

Logger.prototype.error = function(message) {
  console.error(this._createLine('ERROR', message));
};

Logger.prototype.warn = function(message) {
  console.error(this._createLine('WARN', message));
};

exports.Logger = Logger;
