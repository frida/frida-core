SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
  }
  .rodata : {
    *(.rodata*)
  }
  .kernel_addrs : ALIGN(4) {
    . = ALIGN(4);
    _ExAllocatePoolWithTag = .; . += 4;
    _ExFreePoolWithTag = .; . += 4;
    _PsCreateSystemThread = .; . += 4;
    _PsTerminateSystemThread = .; . += 4;
    _PsGetCurrentThreadId = .; . += 4;
    _KeInitializeEvent = .; . += 4;
    _KeWaitForSingleObject = .; . += 4;
    _KeSetEvent = .; . += 4;
    _ZwYieldExecution = .; . += 4;
    _KeBugCheckEx = .; . += 4;
    _MmMapIoSpace = .; . += 4;
    _MmGetPhysicalAddress = .; . += 4;
    _HalGetInterruptVector = .; . += 4;
    _IoConnectInterrupt = .; . += 4;
    _PsActiveProcessHead = .; . += 4;
    _PsInitialSystemProcess = .; . += 4;
    _PsGetProcessId = .; . += 4;
    _PsGetProcessImageFileName = .; . += 4;
    _PsGetProcessPeb = .; . += 4;
    _PsGetCurrentThread = .; . += 4;
    _PsGetThreadProcess = .; . += 4;
    _PsGetThreadId = .; . += 4;
    _PsGetContextThread = .; . += 4;
    _KeStackAttachProcess = .; . += 4;
    _KeUnstackDetachProcess = .; . += 4;
    _ZwCreateFile = .; . += 4;
    _ZwReadFile = .; . += 4;
    _ZwClose = .; . += 4;
    _IoAllocateMdl = .; . += 4;
    _MmBuildMdlForNonPagedPool = .; . += 4;
    _MmMapLockedPagesSpecifyCache = .; . += 4;
    _MmUnmapLockedPages = .; . += 4;
  }
  /* Everything above is only ever read, so a process being instrumented can be shown the very
     same pages; everything below it each copy needs its own of. */
  . = ALIGN(4096);
  _agent_private_start = .;
  .data.rel.ro : {
    *(.data.rel.ro*)
  }
  .got : {
    *(.got*)
  }
  .bss : {
    *(.bss*)
  }
  . = ALIGN(4);
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
