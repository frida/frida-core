const memory = new Map();
let nextBase = 0x10000;

export function allocate(size, at) {
  const base = at ?? nextBase;
  if (at === undefined)
    nextBase += Math.ceil(size / 0x1000) * 0x1000 + 0x1000;
  memory.set(base, new Uint8Array(size));
  return new NativePointer(base);
}

function locate(address) {
  for (const [base, bytes] of memory) {
    if (address >= base && address < base + bytes.length)
      return { bytes, offset: address - base };
  }
  throw new Error(`access violation at 0x${address.toString(16)}`);
}

function view(address, size) {
  const { bytes, offset } = locate(address);
  return new DataView(bytes.buffer, bytes.byteOffset + offset, size);
}

export class NativePointer {
  constructor(value) {
    if (value instanceof NativePointer)
      this.value = value.value;
    else if (typeof value === "string")
      this.value = Number(BigInt(value));
    else if (typeof value === "number")
      this.value = value;
    else
      this.value = Number(value.toString());
  }
  add(delta) { return new NativePointer(this.value + new NativePointer(delta).value); }
  sub(delta) { return new NativePointer(this.value - new NativePointer(delta).value); }
  isNull() { return this.value === 0; }
  equals(other) { return this.value === new NativePointer(other).value; }
  toString(radix = 16) { return radix === 16 ? "0x" + this.value.toString(16) : this.value.toString(radix); }
  toJSON() { return this.toString(); }
  toUInt32() { return this.value >>> 0; }
  readU8(offset = 0) { return view(this.value + offset, 1).getUint8(0); }
  readS8(offset = 0) { return view(this.value + offset, 1).getInt8(0); }
  readU16(offset = 0) { return view(this.value + offset, 2).getUint16(0, true); }
  readS16(offset = 0) { return view(this.value + offset, 2).getInt16(0, true); }
  readU32(offset = 0) { return view(this.value + offset, 4).getUint32(0, true); }
  readS32(offset = 0) { return view(this.value + offset, 4).getInt32(0, true); }
  readU64(offset = 0) { return new UInt64(view(this.value + offset, 8).getBigUint64(0, true)); }
  readS64(offset = 0) { return new Int64(view(this.value + offset, 8).getBigInt64(0, true)); }
  readFloat(offset = 0) { return view(this.value + offset, 4).getFloat32(0, true); }
  readDouble(offset = 0) { return view(this.value + offset, 8).getFloat64(0, true); }
  readPointer(offset = 0) { return new NativePointer(Number(view(this.value + offset, 8).getBigUint64(0, true))); }
  readByteArray(size, offset = 0) { const { bytes, offset: start } = locate(this.value + offset); return bytes.slice(start, start + size).buffer; }
  readUtf8String(length = -1, at = 0) {
    const { bytes, offset } = locate(this.value + at);
    let end = offset;
    if (length === -1) { while (bytes[end] !== 0) end++; } else { end = offset + length; }
    return new TextDecoder().decode(bytes.subarray(offset, end));
  }
  readUtf16String(length = -1, at = 0) {
    const { bytes, offset } = locate(this.value + at);
    let end = offset;
    if (length === -1) { while (bytes[end] !== 0 || bytes[end + 1] !== 0) end += 2; } else { end = offset + length * 2; }
    return new TextDecoder("utf-16le").decode(bytes.subarray(offset, end));
  }
  writeU8(v, offset = 0) { view(this.value + offset, 1).setUint8(0, v); return this; }
  writeS8(v, offset = 0) { view(this.value + offset, 1).setInt8(0, v); return this; }
  writeU16(v, offset = 0) { view(this.value + offset, 2).setUint16(0, v, true); return this; }
  writeS16(v, offset = 0) { view(this.value + offset, 2).setInt16(0, v, true); return this; }
  writeU32(v, offset = 0) { view(this.value + offset, 4).setUint32(0, v, true); return this; }
  writeS32(v, offset = 0) { view(this.value + offset, 4).setInt32(0, v, true); return this; }
  writeU64(v, offset = 0) { view(this.value + offset, 8).setBigUint64(0, BigInt(v.toString()), true); return this; }
  writeS64(v, offset = 0) { view(this.value + offset, 8).setBigInt64(0, BigInt(v.toString()), true); return this; }
  writeFloat(v, offset = 0) { view(this.value + offset, 4).setFloat32(0, v, true); return this; }
  writeDouble(v, offset = 0) { view(this.value + offset, 8).setFloat64(0, v, true); return this; }
  writePointer(v, offset = 0) { view(this.value + offset, 8).setBigUint64(0, BigInt(new NativePointer(v).value), true); return this; }
  writeByteArray(buffer, at = 0) {
    const source = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : Uint8Array.from(buffer);
    const { bytes, offset } = locate(this.value + at);
    bytes.set(source, offset);
    return this;
  }
}

class Integer64 {
  constructor(value) { this.value = BigInt(value.toString()); }
  toString(radix = 10) { return this.value.toString(radix); }
  toNumber() { return Number(this.value); }
  valueOf() { return Number(this.value); }
  toJSON() { return this.toString(); }
  shl(n) { return new this.constructor(this.value << BigInt(n)); }
  or(o) { return new this.constructor(this.value | BigInt(o.toString())); }
  equals(o) { return this.value === BigInt(o.toString()); }
}
export class UInt64 extends Integer64 {}
export class Int64 extends Integer64 {}

export function install() {
  globalThis.NativePointer = NativePointer;
  globalThis.UInt64 = UInt64;
  globalThis.Int64 = Int64;
  globalThis.ptr = (v) => new NativePointer(v);
  globalThis.NULL = new NativePointer(0);
  globalThis.uint64 = (v) => new UInt64(v);
  globalThis.int64 = (v) => new Int64(v);
  globalThis.Process = { pointerSize: 8, arch: "arm64", platform: "darwin" };
}
