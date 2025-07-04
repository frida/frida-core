const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/release/frida-barebone-agent"));

const start = new NativeFunction(cm._start, "pointer", []);
const bufferPhysicalAddress = start();
console.log("Ready! Buffer is at physical address:", bufferPhysicalAddress);

Object.assign(globalThis, { cm, start });
