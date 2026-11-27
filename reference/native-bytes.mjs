// Copy a genuine Uint8Array or Buffer by its intrinsic byte range, without
// consulting replaceable instance methods or properties.
import { types } from 'node:util';

const uint8Prototype = Object.getPrototypeOf(Uint8Array.prototype);
const uint8Buffer = Object.getOwnPropertyDescriptor(uint8Prototype, 'buffer').get;
const uint8Offset = Object.getOwnPropertyDescriptor(uint8Prototype, 'byteOffset').get;
const uint8Length = Object.getOwnPropertyDescriptor(uint8Prototype, 'byteLength').get;

export const isNativeBuffer = value => Buffer.isBuffer(value) && types.isUint8Array(value);

export const nativeUint8Copy = value => {
  if (!types.isUint8Array(value)) throw new TypeError('Expected a native Uint8Array');
  const source = new Uint8Array(
    uint8Buffer.call(value), uint8Offset.call(value), uint8Length.call(value));
  const bytes = Buffer.alloc(source.byteLength);
  Uint8Array.prototype.set.call(bytes, source);
  return bytes;
};
