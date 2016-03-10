'use strict';

const Fs = require('fs');
const Assert = require('assert');

const JsonUtil = require('webpki.org').JsonUtil;
const Base64Url = require('webpki.org').Base64Url;

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

var aReader = reader.getArrayReader('arr');
aReader.getString();
var inner = aReader.getObjectReader();
inner.getInt('inti');

reader.checkForUnread();
