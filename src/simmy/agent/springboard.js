const SBS = bind({
  module: '/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices',
  cprefix: 'SBS',
  functions: {
    copyFrontmostApplicationDisplayIdentifier:        ['pointer', [                    ]],
    copyLocalizedApplicationNameForDisplayIdentifier: ['pointer', ['pointer'           ]],
    processIDForDisplayIdentifier:                    ['bool',    ['pointer', 'pointer']],
  }
});

const CF = bind({
  module: '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
  cprefix: 'CF',
  functions: {
    release:                          ['void',    ['pointer'                           ]],
    stringGetCStringPtr:              ['pointer', ['pointer', 'uint'                   ]],
    stringGetLength:                  ['long',    ['pointer'                           ]],
    stringGetMaximumSizeForEncoding:  ['long',    ['long', 'uint'                      ]],
    stringGetCString:                 ['bool',    ['pointer', 'pointer', 'long', 'uint']],
  }
});

const kCFStringEncodingUTF8 = 0x08000100;

rpc.exports = {
  getFrontmostApplication() {
    const idObj = SBS.copyFrontmostApplicationDisplayIdentifier();
    if (idObj.isNull())
      return null;

    const id = cfStringToUtf8(idObj);

    const nameObj = SBS.copyLocalizedApplicationNameForDisplayIdentifier(idObj);
    const name = cfStringToUtf8(nameObj);

    const pidBuf = Memory.alloc(4);
    SBS.processIDForDisplayIdentifier(idObj, pidBuf);
    const pid = pidBuf.readU32();

    CF.release(nameObj);
    CF.release(idObj);

    if (pid === 0)
      return null;

    return [
      id,
      name,
      pid,
    ];
  }
};

function bind({ module, cprefix, functions }) {
  const mod = Process.getModuleByName(module);
  const nfOpts = { exceptions: 'propagate' };
  return Object.fromEntries(Object.entries(functions).map(([name, [retType, argTypes]]) => [
    name,
    new NativeFunction(mod.getExportByName(cprefix + name.charAt(0).toUpperCase() + name.slice(1)), retType, argTypes, nfOpts)
  ]));
}

function cfStringToUtf8(cfstr) {
  const direct = CF.stringGetCStringPtr(cfstr, kCFStringEncodingUTF8);
  if (!direct.isNull())
    return direct.readUtf8String();

  const len16 = CF.stringGetLength(cfstr);
  const maxBytes = CF.stringGetMaximumSizeForEncoding(len16, kCFStringEncodingUTF8).valueOf() + 1;
  const buf = Memory.alloc(maxBytes);
  CF.stringGetCString(cfstr, buf, maxBytes, kCFStringEncodingUTF8);
  return buf.readUtf8String();
}
