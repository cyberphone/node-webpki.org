'use strict';

const Fs = require('fs');
const Assert = require('assert');

const JsonUtil = require('webpki.org').JsonUtil;
const Base64Url = require('webpki.org').Base64Url;
const ByteArray = require('webpki.org').ByteArray;
const Big = require('webpki.org').Big;

const someObject = {

  myint: 7,
  ablob: 'hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc',
  arr: ["a string", {inti: 7}]

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

Assert.deepEqual(Base64Url.decode(someObject.ablob), reader.getBinary('ablob'));

Assert.throws(
  () => {
    reader.checkForUnread();
  }
);

var aReader = reader.getArray('arr');
aReader.getString();
var inner = aReader.getObject();
inner.getInt('inti');

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
