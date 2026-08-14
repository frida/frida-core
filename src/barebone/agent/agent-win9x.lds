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
    _Fatal_Error_Handler = .; . += 4;
    _Debug_Printf_Service = .; . += 4;
    _HeapAllocate = .; . += 4;
    _HeapFree = .; . += 4;
    _PageAllocate = .; . += 4;
    _PageFree = .; . += 4;
    _Create_Thread = .; . += 4;
    _Get_System_Time = .; . += 4;
    _Get_Cur_Thread_Handle = .; . += 4;
    _Create_Semaphore = .; . += 4;
    _Wait_Semaphore = .; . += 4;
    _Signal_Semaphore = .; . += 4;
    _Release_Time_Slice = .; . += 4;
    _PageModifyPermissions = .; . += 4;
    _MapPhysToLinear = .; . += 4;
    _CopyPageTable = .; . += 4;
    _VPICD_Virtualize_IRQ = .; . += 4;
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
