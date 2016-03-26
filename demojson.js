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
  null: null,
  arr: ["a string", {inti: 7}, null]

};

const reader = new JsonUtil.ObjectReader(someObject);

Assert.equal(reader.getInt('myint'), 7);

Assert.deepEqual(Base64Url.decode(someObject.ablob), reader.getBinary('ablob'));

Assert.equal(reader.isNull('null'), true);
Assert.equal(reader.isNull('myint'), false);

const aReader = reader.getArray('arr');
aReader.getString();
var inner = aReader.getObject();
inner.getInt('inti');
Assert.equal(aReader.isNull(), true);
aReader.scanItem();

reader.checkForUnread();

