SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
    *(.rodata*)
  }
  .dynstr : {
    *(.dynstr)
  }
  .dynsym : {
    *(.dynsym)
  }
  .gnu.hash : {
    *(.gnu.hash)
  }
  .hash : {
    *(.hash)
  }
  .note.gnu.build-id : {
    *(.note.gnu.build-id)
  }
  .note.android.ident : {
    *(.note.android.ident)
  }
  .got : ALIGN(64) {
    *(.got*)
    . = ALIGN(64);
  }
}
