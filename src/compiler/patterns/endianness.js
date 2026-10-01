export const $littleEndian = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;
