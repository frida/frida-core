const PID_NAME_SIZE = 4 + 32;

const KERNEL_MAP = ptr("0xfffffff0076ce618");
const KHEAP_DEFAULT = ptr("0xfffffff0076c82c0");

const KALLOC = ptr("0xfffffff007a3c278");
const KFREE = ptr("0xfffffff007a3c338");
const KMEM_ALLOC_ALIGNED = ptr("0xfffffff007ad2f84");

const VM_KERN_MEMORY_NONE = NULL;

const kalloc = new NativeFunction(KALLOC, "pointer", ["size_t"]);
const kfree = new NativeFunction(KALLOC, "void", ["pointer", "size_t"]);
const kmemAllocAligned = new NativeFunction(KMEM_ALLOC_ALIGNED, "int", ["pointer", "pointer", "size_t", "pointer"]);

const mod = new RustModule(File.readAllText("/Users/oleavr/src/frida-barebone-ios/prototyping/enumerate.rs"));
console.log("Rust module loaded, enumerate_processes() is at:", mod.enumerate_processes);

const _enumerateProcesses = new NativeFunction(mod.enumerate_processes, "int", ["pointer", "int"]);

function kallocAligned(size: number): NativePointer {
    const addrp = kalloc(8);
    const kr = kmemAllocAligned(KERNEL_MAP, addrp, size, VM_KERN_MEMORY_NONE);
    if (kr != 0) {
        throw new Error(`kmem_alloc_aligned() failed: ${kr}`);
    }
    return addrp.readPointer();
}

function enumerateProcesses() {
    const size = 128 * 1024;
    const buffer = kalloc(size);
    const result = [];
    const n = _enumerateProcesses(buffer, size);
    let offset = 0;
    for (let i = 0; i !== n; i++) {
        const entry = buffer.add(offset);
        result.push({
            pid: entry.readU32(),
            name: entry.add(4).readUtf8String(32),
        });
        offset += PID_NAME_SIZE;
    }
    kfree(buffer, size);
    return result;
}

Object.assign(globalThis, {
    mod,
    kalloc,
    kallocAligned,
    enumerateProcesses,
});
