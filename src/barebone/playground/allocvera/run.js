const data = File.readAllBytes("./target/aarch64-unknown-none/release/allocvera")
const cm = new CModule(data)
const start = new NativeFunction(cm._start, "pointer", []);
start()
$gdb.continue()
Object.assign(globalThis, { cm, start });
