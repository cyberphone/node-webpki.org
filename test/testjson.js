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
/*                            TestJson                            */
/*================================================================*/

// Unit testing suite for JsonUtil

const Fs = require('fs');
const Assert = require('assert');

const JsonUtil = require('..').JsonUtil;
const Logging = require('..').Logging;
const Base64Url = require('..').Base64Url;
const ByteArray = require('..').ByteArray;
const Big = require('..').Big;

var logger = new Logging.Logger(__filename);
logger.info('Starting');

const pretty = Fs.readFileSync(__dirname + '/pretty.txt').toString();
var begin = 0;
for (var q = 1; q < pretty.length; q++) {
  if (pretty.charAt(q - 1) == '\n' && pretty.charAt(q) == '\n') {
    var formatted = pretty.substring(begin, q);
    begin = q + 1;
    var json = new JsonUtil.ObjectReader(JSON.parse(formatted));
    Assert.equal(formatted, json.toString());
  }
}

const escaped = JSON.parse('{"esc":"\\"\\\\><& \\u000a\\u0041\\u20ac\'","@t":[6.5,true,null],"-":null}');
Assert.equal('{\n  "esc": "\\"\\\\><& \\nA\u20ac\'",\n  "@t": [6.5,true,null],\n  "-": null\n}\n',
             new JsonUtil.ObjectReader(escaped).toString());
Assert.equal('{\n  esc: "\\"\\\\\\u003e\\u003c\\u0026 \\nA\u20ac\'",\n  "@t": [6.5,true,null],\n  "-": null\n}',
             new JsonUtil.ObjectReader(escaped).toString(JsonUtil.FORMAT_JAVASCRIPT));
             
const someObject = {

  myint: 7,
  ablob: 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc',
  arr: ["a string", {inti: 9},true]

};

var reader = new JsonUtil.ObjectReader(someObject);

Assert.doesNotThrow(
  () => {
    if (reader.getInt('myint') != 7) {
      throw new RangeError('Wrong integer');
    }
  });

Assert.throws(
  () => {
    reader.getString('myint');
  }
);

Assert.throws(
  () => {
    new JsonUtil.ObjectReader({my:6.5}).getInt('my');
  }
);

Assert.doesNotThrow(
  () => {
    new JsonUtil.ObjectReader({my:9007199254740991}).getInt('my');
  }
);

Assert.throws(
  () => {
    new JsonUtil.ObjectReader({my:9007199254740992}).getInt('my');
  }
);

Assert.doesNotThrow(
  () => {
    new JsonUtil.ObjectWriter().setInt('my',9007199254740991);
  }
);

Assert.throws(
  () => {
    new JsonUtil.ObjectWriter().setInt('my', 9007199254740992);
  }
);

Assert.doesNotThrow(
  () => {
    new JsonUtil.ArrayReader([-9007199254740991]).getInt();
  }
);

Assert.throws(
  () => {
    new JsonUtil.ArrayReader([9007199254740992]).getInt();
  }
);

Assert.deepEqual(Base64Url.decode(someObject.ablob), reader.getBinary('ablob'));

Assert.throws(
  () => {
    reader.checkForUnread();
  }
);

var aReader = reader.getArray('arr');
aReader.getString();
var inner = aReader.getObject();
Assert.equal(inner.getInt('inti'), 9);
Assert.equal(aReader.getBoolean(), true);


reader.checkForUnread();

var utf8bin = new Uint8Array([0xE2, 0x82, 0xAC, 0xC3, 0xA5, 0xC3, 0xB6, 0x6B]);
var theString = '\u20ac\u00e5\u00f6\k';
Assert.equal(ByteArray.utf8ToString(utf8bin), theString);
Assert.deepEqual(ByteArray.stringToUtf8(theString), utf8bin);

Assert.throws(
  () => {
new JsonUtil.ObjectReader(new JsonUtil.ObjectWriter()
  .setBigDecimal('big2',new Big(5)).getRootObject()).getBigDecimal('big2',2);
  }
);

Assert.ok(new JsonUtil.ObjectReader(new JsonUtil.ObjectWriter()
  .setBigDecimal('big2',new Big(5)).getRootObject()).getBigDecimal('big2').eq(new Big(5)));

Assert.ok(new JsonUtil.ObjectReader(new JsonUtil.ObjectWriter()
  .setBigDecimal('big2',new Big(5),2).getRootObject()).getBigDecimal('big2', 2).eq(new Big(5)));


Assert.ok(new JsonUtil.ObjectReader(new JsonUtil.ObjectWriter()
  .setBigDecimal('big2',new Big(5.25)).getRootObject()).getBigDecimal('big2', 2).eq(new Big(5.25)));

logger.info('Done!');
