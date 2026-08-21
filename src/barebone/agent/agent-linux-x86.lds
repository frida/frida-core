SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
  }
  .rel.dyn : {
    _agent_relocs_start = .;
    *(.rel.dyn)
    _agent_relocs_end = .;
  }
  .rodata : {
    *(.rodata*)
  }
  .kernel_addrs : ALIGN(4) {
    . = ALIGN(4);
    _printk = .; . += 4;
    _panic = .; . += 4;
    _kthread_create_on_node = .; . += 4;
    _init_task = .; . += 4;
    _tasklist_lock = .; . += 4;
    __raw_read_lock = .; . += 4;
    __raw_read_unlock = .; . += 4;
    _get_task_exe_file = .; . += 4;
    _file_path = .; . += 4;
    _fput = .; . += 4;
    _copy_from_kernel_nofault = .; . += 4;
    _wake_up_process = .; . += 4;
    _kmalloc_noprof = .; . += 4;
    _kmalloc = .; . += 4;
    _kfree = .; . += 4;
    _execmem_alloc = .; . += 4;
    _execmem_free = .; . += 4;
    _module_alloc = .; . += 4;
    _module_memfree = .; . += 4;
    _msleep = .; . += 4;
    _schedule = .; . += 4;
    _ktime_get_ns = .; . += 4;
    _ktime_get_real_ts64 = .; . += 4;
    _request_threaded_irq = .; . += 4;
    _ioremap = .; . += 4;
    _virt_to_phys = .; . += 4;
    _current_task = .; . += 4;
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
  .data : {
    *(.data*)
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
