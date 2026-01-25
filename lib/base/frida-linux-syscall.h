#ifndef __FRIDA_LINUX_SYSCALL_H__
#define __FRIDA_LINUX_SYSCALL_H__

#include <linux/unistd.h>
#include <sys/syscall.h>

#undef SYS_perf_event_open
#undef SYS_process_vm_readv
#undef SYS_process_vm_writev
#undef SYS_memfd_create
#undef SYS_bpf
#undef SYS_pidfd_open
#undef SYS_pidfd_getfd

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define SYS_perf_event_open    336
# define SYS_process_vm_readv   347
# define SYS_process_vm_writev  348
# define SYS_memfd_create       356
# define SYS_bpf                357
# define SYS_pidfd_open         434
# define SYS_pidfd_getfd        438
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define SYS_perf_event_open    298
# define SYS_process_vm_readv   310
# define SYS_process_vm_writev  311
# define SYS_memfd_create       319
# define SYS_bpf                321
# define SYS_pidfd_open         434
# define SYS_pidfd_getfd        438
#elif defined (HAVE_ARM)
# define SYS_perf_event_open    (__NR_SYSCALL_BASE + 364)
# define SYS_process_vm_readv   (__NR_SYSCALL_BASE + 376)
# define SYS_process_vm_writev  (__NR_SYSCALL_BASE + 377)
# define SYS_memfd_create       (__NR_SYSCALL_BASE + 385)
# define SYS_bpf                (__NR_SYSCALL_BASE + 386)
# define SYS_pidfd_open         (__NR_SYSCALL_BASE + 434)
# define SYS_pidfd_getfd        (__NR_SYSCALL_BASE + 438)
#elif defined (HAVE_ARM64)
# define SYS_perf_event_open    241
# define SYS_process_vm_readv   270
# define SYS_process_vm_writev  271
# define SYS_memfd_create       279
# define SYS_bpf                280
# define SYS_pidfd_open         434
# define SYS_pidfd_getfd        438
#elif defined (HAVE_MIPS)
# if _MIPS_SIM == _MIPS_SIM_ABI32
#  define SYS_perf_event_open   (__NR_Linux + 333)
#  define SYS_process_vm_readv  (__NR_Linux + 345)
#  define SYS_process_vm_writev (__NR_Linux + 346)
#  define SYS_memfd_create      (__NR_Linux + 354)
#  define SYS_bpf               (__NR_Linux + 355)
#  define SYS_pidfd_open        (__NR_Linux + 434)
#  define SYS_pidfd_getfd       (__NR_Linux + 438)
# elif _MIPS_SIM == _MIPS_SIM_ABI64
#  define SYS_perf_event_open   (__NR_Linux + 292)
#  define SYS_process_vm_readv  (__NR_Linux + 304)
#  define SYS_process_vm_writev (__NR_Linux + 305)
#  define SYS_memfd_create      (__NR_Linux + 314)
#  define SYS_bpf               (__NR_Linux + 315)
#  define SYS_pidfd_open        (__NR_Linux + 434)
#  define SYS_pidfd_getfd       (__NR_Linux + 438)
# elif _MIPS_SIM == _MIPS_SIM_NABI32
#  define SYS_perf_event_open   (__NR_Linux + 296)
#  define SYS_process_vm_readv  (__NR_Linux + 309)
#  define SYS_process_vm_writev (__NR_Linux + 310)
#  define SYS_memfd_create      (__NR_Linux + 318)
#  define SYS_bpf               (__NR_Linux + 319)
#  define SYS_pidfd_open        (__NR_Linux + 434)
#  define SYS_pidfd_getfd       (__NR_Linux + 438)
# else
#  error Unexpected MIPS ABI
# endif
#elif defined (HAVE_RISCV)
# if GLIB_SIZEOF_VOID_P == 8
#  define SYS_perf_event_open    241
#  define SYS_process_vm_readv   270
#  define SYS_process_vm_writev  271
#  define SYS_memfd_create       279
#  define SYS_bpf                280
#  define SYS_pidfd_open         434
#  define SYS_pidfd_getfd        438
# else
#  error RISC-V 32-bit not yet supported
# endif
#else
# error FIXME
#endif

#endif
