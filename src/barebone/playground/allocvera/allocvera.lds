SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
  }
  .rodata : {
    *(.rodata*)
  }
  .data.rel.ro : {
    *(.data.rel.ro*)
  }
  .got : {
    *(.got*)
  }
  .panic_info : ALIGN(1024) {
    *(.bss.panic_info)
  }
  .bss : {
    *(.bss*)
  }
  . = ALIGN(8);
  _heap_start = .;
}

VERSION {
  {
    global:
      _start;

    local:
      *;
  };
}
