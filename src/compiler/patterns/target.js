export const $target = Process.pointerSize === 8 ? 0 : (Process.arch === "ia32" && Process.platform !== "windows") ? 2 : 1;
