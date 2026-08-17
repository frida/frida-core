SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
  }
  .rodata : {
    *(.rodata*)
  }
  .kernel_addrs : ALIGN(8) {
    . = ALIGN(8);
    _panic = .; . += 8;
    _IOLog = .; . += 8;
    _kalloc = .; . += 8;
    _kfree = .; . += 8;
    _kernel_thread_start = .; . += 8;
    _assert_wait = .; . += 8;
    _assert_wait_timeout = .; . += 8;
    _thread_block = .; . += 8;
    _thread_wakeup = .; . += 8;
    _mach_absolute_time = .; . += 8;
    _absolutetime_to_nanoseconds = .; . += 8;
    _clock_get_calendar_microtime = .; . += 8;
    _ml_io_map = .; . += 8;
    _ml_vtophys = .; . += 8;
    __ZN9IOService11getPlatformEv = .; . += 8;
    __ZN9IOServiceC2Ev = .; . += 8;
    __ZN8OSSymbol17withCStringNoCopyEPKc = .; . += 8;
    __ZN6OSData9withBytesEPKvj = .; . += 8;
    _kalloc_data = .; . += 8;
    _kfree_data = .; . += 8;
    _wakeup = .; . += 8;
    _sock_socket = .; . += 8;
    _sock_connect = .; . += 8;
    _sock_send = .; . += 8;
    _sock_receive = .; . += 8;
    _sock_close = .; . += 8;
  }
  .data.rel.ro : {
    *(.data.rel.ro*)
  }
  .got : {
    *(.got*)
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
