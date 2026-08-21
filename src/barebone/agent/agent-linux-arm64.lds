SECTIONS {
  .text : {
    *(.text.entrypoint)
    *(.text*)
  }
  .rela.dyn : {
    _agent_relocs_start = .;
    *(.rela.dyn)
    _agent_relocs_end = .;
  }
  .rodata : {
    *(.rodata*)
  }
  .kernel_addrs : ALIGN(8) {
    . = ALIGN(8);
    __printk = .; . += 8;
    _printk = .; . += 8;
    _panic = .; . += 8;
    _kthread_create_on_node = .; . += 8;
    _init_task = .; . += 8;
    _tasklist_lock = .; . += 8;
    __raw_read_lock = .; . += 8;
    __raw_read_unlock = .; . += 8;
    _get_task_exe_file = .; . += 8;
    _file_path = .; . += 8;
    _fput = .; . += 8;
    _copy_from_kernel_nofault = .; . += 8;
    _wake_up_process = .; . += 8;
    ___kmalloc_noprof = .; . += 8;
    _kmalloc = .; . += 8;
    _kfree = .; . += 8;
    _execmem_alloc = .; . += 8;
    _set_memory_rw = .; . += 8;
    _execmem_free = .; . += 8;
    _module_alloc = .; . += 8;
    _module_memfree = .; . += 8;
    _msleep = .; . += 8;
    _schedule = .; . += 8;
    _ktime_get_mono_fast_ns = .; . += 8;
    _ktime_get_real_ts64 = .; . += 8;
    _request_threaded_irq = .; . += 8;
    _generic_ioremap_prot = .; . += 8;
    _memstart_addr = .; . += 8;
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
