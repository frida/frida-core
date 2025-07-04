const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/release/frida-barebone-agent"));
console.log("CModule loaded!");

Object.assign(globalThis, { cm });
