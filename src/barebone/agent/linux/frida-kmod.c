/*
 * Glue between the Rust agent and the Linux kernel it is loaded into.
 *
 * Everything the agent needs from the kernel lives here rather than in Rust,
 * because all of it is version- and config-dependent: struct layouts, inline helpers
 * that are really macros, the character-device and uaccess APIs, and which of
 * kallsyms' entry points happen to be exported this release. Compiling against the
 * target kernel's own headers is what keeps that knowledge correct.
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kasan.h>
#include <linux/kfifo.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#ifdef CONFIG_ARM64
# include <asm/cacheflush.h>
#endif

/* Mirrors GumPageProtection. */
#define FRIDA_PAGE_WRITE   (1 << 1)
#define FRIDA_PAGE_EXECUTE (1 << 2)

typedef int (* FridaFoundSymbolFunc) (const char * name, u64 address, void * user_data);
typedef int (* FridaFoundModuleFunc) (const char * name, const char * version, u64 base, u64 size,
    void * user_data);
typedef void (* FridaThreadEntry) (void * parameter, int wait_result);

struct frida_thread_ctx
{
  FridaThreadEntry entry;
  void * parameter;
};

struct frida_writable_alias
{
  struct list_head node;
  void * mapping;
  unsigned long first_page;
  unsigned int n_pages;
};

struct frida_symbol_visit_ctx
{
  FridaFoundSymbolFunc func;
  void * user_data;
};

int frida_agent_start (void);
void frida_agent_stop (void);

u64 frida_kmod_find_symbol (const char * name);
void frida_kmod_wake (void);
void frida_kmod_yield (void);

static void frida_resolve_kallsyms (void);
static void frida_resolve_kernel_range (void);
static void * frida_resolve_unexported (const char * name);
static int frida_thread_trampoline (void * data);
static int frida_dev_open (struct inode * inode, struct file * file);
static int frida_dev_release (struct inode * inode, struct file * file);
static ssize_t frida_dev_read (struct file * file, char __user * buffer, size_t size,
    loff_t * offset);
static ssize_t frida_dev_write (struct file * file, const char __user * buffer, size_t size,
    loff_t * offset);
static __poll_t frida_dev_poll (struct file * file, struct poll_table_struct * wait);
static struct page * frida_page_for_virtual (unsigned long address);
static bool frida_is_vmalloc_or_module_addr (const void * x);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 4, 0)
static int frida_on_each_symbol (void * data, const char * name, unsigned long address);
#else
static int frida_on_each_symbol (void * data, const char * name, struct module * mod,
    unsigned long address);
#endif
static bool frida_should_wake (unsigned int seq);
static void frida_strip_module_suffix (char * rendered);

static DECLARE_WAIT_QUEUE_HEAD (frida_wq);
static atomic_t frida_wake_seq = ATOMIC_INIT (0);

static u64 frida_kernel_base;
static u64 frida_kernel_size;

static typeof (&kallsyms_lookup_name) frida_kallsyms_lookup_name_impl;
static typeof (&kallsyms_on_each_symbol) frida_kallsyms_on_each_symbol_impl;
static struct list_head * frida_modules;
static struct mutex * frida_module_mutex;
static typeof (&set_memory_ro) frida_set_memory_ro_impl;
static typeof (&set_memory_rw) frida_set_memory_rw_impl;
static typeof (&set_memory_x) frida_set_memory_x_impl;
static typeof (&set_memory_nx) frida_set_memory_nx_impl;

static LIST_HEAD (frida_writable_aliases);
static DEFINE_MUTEX (frida_writable_aliases_mutex);

#define FRIDA_LINK_CAPACITY (1024 * 1024)

#define FRIDA_WAIT_FOREVER_SLICE_US (1000 * 1000)

static DECLARE_KFIFO_PTR (frida_to_client, u8);
static DECLARE_KFIFO_PTR (frida_from_client, u8);
static DEFINE_MUTEX (frida_link_mutex);
static DECLARE_WAIT_QUEUE_HEAD (frida_readable_wq);
static atomic_t frida_client_count = ATOMIC_INIT (0);
static bool frida_link_registered;

static const struct file_operations frida_dev_fops =
{
  .owner = THIS_MODULE,
  .open = frida_dev_open,
  .release = frida_dev_release,
  .read = frida_dev_read,
  .write = frida_dev_write,
  .poll = frida_dev_poll,
};

static struct miscdevice frida_dev =
{
  .minor = MISC_DYNAMIC_MINOR,
  .name = "frida",
  .fops = &frida_dev_fops,
  .mode = 0600,
};

static int __init
frida_kmod_init (void)
{
  frida_resolve_kallsyms ();
  frida_resolve_kernel_range ();

  return frida_agent_start ();
}

static void __exit
frida_kmod_exit (void)
{
  frida_agent_stop ();
}

module_init (frida_kmod_init);
module_exit (frida_kmod_exit);

MODULE_LICENSE ("GPL");
MODULE_DESCRIPTION ("Frida instrumentation agent");
MODULE_VERSION ("1.0.0");

static void
frida_resolve_kallsyms (void)
{
  frida_kallsyms_lookup_name_impl = frida_resolve_unexported ("kallsyms_lookup_name");
  frida_kallsyms_on_each_symbol_impl = frida_resolve_unexported ("kallsyms_on_each_symbol");

  if (frida_kallsyms_lookup_name_impl == NULL)
    {
      printk (KERN_WARNING "frida: kallsyms_lookup_name unavailable\n");
      return;
    }

  frida_modules = (struct list_head *) frida_kallsyms_lookup_name_impl ("modules");
  frida_module_mutex = (struct mutex *) frida_kallsyms_lookup_name_impl ("module_mutex");

  /*
   * GKI trims its export table to the KMI symbol list, which leaves set_memory_*()
   * callable but unexported. Being absent from Module.symvers only stops the module
   * loader from resolving them, so go through kallsyms like everything else here.
   */
  frida_set_memory_ro_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_ro");
  frida_set_memory_rw_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_rw");
  frida_set_memory_x_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_x");
  frida_set_memory_nx_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_nx");
}

static void
frida_resolve_kernel_range (void)
{
  u64 start, end;

  start = frida_kmod_find_symbol ("_stext");
  end = frida_kmod_find_symbol ("_end");
  if (start == 0 || end == 0)
    return;

  frida_kernel_base = start;
  frida_kernel_size = end - start;
}

/*
 * kallsyms_lookup_name() and kallsyms_on_each_symbol() stopped being exported in
 * 5.7. A kprobe registered by symbol name resolves an address without needing an
 * export, which is the standard way back in.
 */
static void *
frida_resolve_unexported (const char * name)
{
  struct kprobe kp = { .symbol_name = name };
  void * address;

  if (register_kprobe (&kp) < 0)
    return NULL;
  address = kp.addr;
  unregister_kprobe (&kp);

  return address;
}

void
frida_kmod_log (const char * message)
{
  printk (KERN_INFO "%s", message);
}

void
frida_kmod_panic (const char * message)
{
  panic ("%s", message);
}

int
frida_kmod_spawn_thread (FridaThreadEntry entry,
                         void * parameter)
{
  struct frida_thread_ctx * ctx;
  struct task_struct * task;

  ctx = kmalloc (sizeof (struct frida_thread_ctx), GFP_KERNEL);
  ctx->entry = entry;
  ctx->parameter = parameter;

  task = kthread_run (frida_thread_trampoline, ctx, "frida-agent");
  if (IS_ERR (task))
    {
      kfree (ctx);
      return PTR_ERR (task);
    }

  return 0;
}

static int __nocfi
frida_thread_trampoline (void * data)
{
  struct frida_thread_ctx ctx = *((struct frida_thread_ctx *) data);

  kfree (data);

  ctx.entry (ctx.parameter, 0);

  return 0;
}

void *
frida_kmod_alloc (size_t size)
{
  return kvmalloc (size, GFP_KERNEL);
}

void
frida_kmod_free (void * ptr,
                 size_t size)
{
  kvfree (ptr);
}

/*
 * Code slabs have to be page-granular and live somewhere set_memory_x() accepts,
 * which rules out the slab allocator and its sub-page objects.
 */
void *
frida_kmod_alloc_code (size_t size)
{
  return __vmalloc (PAGE_ALIGN (size), GFP_KERNEL | __GFP_ZERO);
}

void
frida_kmod_free_code (void * ptr,
                      size_t size)
{
  vfree (ptr);
}

void
frida_kmod_own_range (u64 * base,
                      u64 * size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 4, 0)
  *base = (u64) (uintptr_t) THIS_MODULE->mem[MOD_TEXT].base;
  *size = THIS_MODULE->mem[MOD_TEXT].size;
#else
  *base = (u64) (uintptr_t) THIS_MODULE->core_layout.base;
  *size = THIS_MODULE->core_layout.size;
#endif
}

/*
 * The transport is a character device rather than a socket the agent dials out on:
 * userspace decides when to attach, needs no network namespace to reach us, and the
 * relay on the other side is whatever the operator points at /dev/frida. The 4-byte
 * length prefix framing is done by the agent, so this is a plain byte stream.
 */
int
frida_kmod_link_open (void)
{
  int res;

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
  if (res != 0)
    return res;

  res = kfifo_alloc (&frida_from_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
  if (res != 0)
    goto free_to_client;

  res = misc_register (&frida_dev);
  if (res != 0)
    goto free_from_client;
  frida_link_registered = true;

  printk (KERN_INFO "frida: listening on /dev/%s\n", frida_dev.name);

  return 0;

free_from_client:
  kfifo_free (&frida_from_client);
free_to_client:
  kfifo_free (&frida_to_client);

  return res;
}

int
frida_kmod_link_send (const void * data,
                      size_t size)
{
  unsigned int written;

  /* Nothing is listening yet, or the client cannot keep up: the agent's replies are
   * only meaningful to a client that is still there, so drop them rather than stall
   * the runtime. */
  if (atomic_read (&frida_client_count) == 0)
    return -ENOTCONN;

  mutex_lock (&frida_link_mutex);
  written = kfifo_in (&frida_to_client, data, size);
  mutex_unlock (&frida_link_mutex);

  if (written != size)
    return -ENOSPC;

  wake_up_interruptible (&frida_readable_wq);

  return 0;
}

long
frida_kmod_link_recv (void * data,
                      size_t size)
{
  unsigned int n;

  mutex_lock (&frida_link_mutex);
  n = kfifo_out (&frida_from_client, data, size);
  mutex_unlock (&frida_link_mutex);

  return n;
}

void
frida_kmod_link_close (void)
{
  if (!frida_link_registered)
    return;
  frida_link_registered = false;

  misc_deregister (&frida_dev);

  kfifo_free (&frida_from_client);
  kfifo_free (&frida_to_client);
}

/* One client at a time: the protocol is a single conversation, and two readers
 * would each get half of every frame. */
static int
frida_dev_open (struct inode * inode,
                struct file * file)
{
  if (atomic_cmpxchg (&frida_client_count, 0, 1) != 0)
    return -EBUSY;

  return nonseekable_open (inode, file);
}

static int
frida_dev_release (struct inode * inode,
                   struct file * file)
{
  mutex_lock (&frida_link_mutex);
  kfifo_reset (&frida_to_client);
  kfifo_reset (&frida_from_client);
  mutex_unlock (&frida_link_mutex);

  atomic_set (&frida_client_count, 0);

  return 0;
}

static ssize_t
frida_dev_read (struct file * file,
                char __user * buffer,
                size_t size,
                loff_t * offset)
{
  unsigned int copied;
  int res;

  while (kfifo_is_empty (&frida_to_client))
    {
      if ((file->f_flags & O_NONBLOCK) != 0)
        return -EAGAIN;

      if (wait_event_interruptible (frida_readable_wq, !kfifo_is_empty (&frida_to_client)) != 0)
        return -ERESTARTSYS;
    }

  mutex_lock (&frida_link_mutex);
  res = kfifo_to_user (&frida_to_client, buffer, size, &copied);
  mutex_unlock (&frida_link_mutex);

  return (res != 0) ? res : copied;
}

static ssize_t
frida_dev_write (struct file * file,
                 const char __user * buffer,
                 size_t size,
                 loff_t * offset)
{
  unsigned int copied;
  int res;

  mutex_lock (&frida_link_mutex);
  res = kfifo_from_user (&frida_from_client, buffer, size, &copied);
  mutex_unlock (&frida_link_mutex);

  if (res != 0)
    return res;

  frida_kmod_wake ();

  return copied;
}

static __poll_t
frida_dev_poll (struct file * file,
                struct poll_table_struct * wait)
{
  __poll_t events = EPOLLOUT | EPOLLWRNORM;

  poll_wait (file, &frida_readable_wq, wait);

  if (!kfifo_is_empty (&frida_to_client))
    events |= EPOLLIN | EPOLLRDNORM;

  return events;
}

/*
 * Two-phase wait: the caller reads the sequence number, checks its condition, and
 * only then commits to sleeping. A wakeup that lands in between bumps the sequence,
 * so the commit returns immediately instead of sleeping through it.
 */
unsigned int
frida_kmod_wait_prepare (void)
{
  return (unsigned int) atomic_read (&frida_wake_seq);
}

void
frida_kmod_wait_commit (unsigned int seq,
                        s64 timeout_us)
{
  s64 capped_timeout_us;
  long timeout;

  /*
   * Every wait is bounded and uninterruptible. Interruptible would be wrong twice
   * over: a kernel thread with a signal pending gets it back immediately, turning
   * each sleep into a no-op and the caller's loop into a spin, and an unbounded
   * uninterruptible sleep would leave the thread unkillable. A caller asking to wait
   * forever gets a long slice instead — anything with something to say bumps the
   * sequence, so this costs latency to nobody.
   */
  capped_timeout_us = (timeout_us < 0)
      ? FRIDA_WAIT_FOREVER_SLICE_US
      : min_t (s64, timeout_us, FRIDA_WAIT_FOREVER_SLICE_US);
  timeout = max_t (long, (capped_timeout_us * HZ) / USEC_PER_SEC, 1);

  wait_event_timeout (frida_wq, frida_should_wake (seq), timeout);
}

/*
 * Queued input has to be level-triggered, not just the edge that delivered it. The
 * agent drains the fifo before arming its wait, so a write landing in between would
 * bump the sequence that the arming then reads as its baseline — and the agent would
 * sleep with a frame already waiting.
 */
static bool
frida_should_wake (unsigned int seq)
{
  if ((unsigned int) atomic_read (&frida_wake_seq) != seq)
    return true;

  return !kfifo_is_empty (&frida_from_client);
}

void
frida_kmod_wake (void)
{
  atomic_inc (&frida_wake_seq);
  wake_up_all (&frida_wq);
}

/*
 * A kernel thread that loops without reaching the scheduler takes the machine down
 * via the hardware watchdog rather than merely running hot, which makes any such loop
 * undiagnosable. Every loop the agent runs calls this.
 */
void
frida_kmod_yield (void)
{
  cond_resched ();
}

s64
frida_kmod_monotonic_micros (void)
{
  return ktime_to_us (ktime_get ());
}

void
frida_kmod_wall_clock_micros (unsigned int * secs,
                              unsigned int * micros)
{
  struct timespec64 ts;

  ktime_get_real_ts64 (&ts);

  *secs = (unsigned int) ts.tv_sec;
  *micros = (unsigned int) (ts.tv_nsec / 1000);
}

/* Handed to JavaScript as a GumThreadId, so it has to fit in the 48 bits a
 * double represents exactly. */
u64
frida_kmod_current_thread_id (void)
{
  return ((u64) (uintptr_t) current) & ((1ULL << 48) - 1);
}

int
frida_kmod_protect (u64 address,
                    size_t size,
                    unsigned int gum_prot)
{
  unsigned long start = address & PAGE_MASK;
  unsigned long end = PAGE_ALIGN (address + size);
  int n_pages = (end - start) / PAGE_SIZE;

  if (frida_set_memory_ro_impl == NULL)
    return 0;

  if ((gum_prot & FRIDA_PAGE_WRITE) != 0)
    {
      if (frida_set_memory_nx_impl (start, n_pages) != 0)
        return 0;
      return frida_set_memory_rw_impl (start, n_pages) == 0;
    }

  if (frida_set_memory_ro_impl (start, n_pages) != 0)
    return 0;

  if ((gum_prot & FRIDA_PAGE_EXECUTE) != 0)
    return frida_set_memory_x_impl (start, n_pages) == 0;

  return 1;
}

/*
 * A second mapping of the same physical pages, writable regardless of what the
 * primary mapping allows. This is how the agent lands hooks in text that
 * STRICT_KERNEL_RWX has made read-only.
 */
void *
frida_kmod_remap_writable (u64 first_page,
                           unsigned int n_pages)
{
  struct page ** pages;
  unsigned int i;
  void * mapping;
  struct frida_writable_alias * alias;

  pages = kmalloc_array (n_pages, sizeof (struct page *), GFP_KERNEL);
  for (i = 0; i != n_pages; i++)
    pages[i] = frida_page_for_virtual (first_page + ((unsigned long) i * PAGE_SIZE));

  mapping = vmap (pages, n_pages, VM_MAP, PAGE_KERNEL);

  kfree (pages);

  if (mapping == NULL)
    return NULL;

  alias = kmalloc (sizeof (struct frida_writable_alias), GFP_KERNEL);
  alias->mapping = mapping;
  alias->first_page = first_page;
  alias->n_pages = n_pages;

  mutex_lock (&frida_writable_aliases_mutex);
  list_add (&alias->node, &frida_writable_aliases);
  mutex_unlock (&frida_writable_aliases_mutex);

  return mapping;
}

void
frida_kmod_unmap_writable (void * mapping)
{
  struct frida_writable_alias * alias = NULL, * candidate;
  unsigned long mapped_size;

  mutex_lock (&frida_writable_aliases_mutex);
  list_for_each_entry (candidate, &frida_writable_aliases, node)
    {
      if (candidate->mapping == mapping)
        {
          alias = candidate;
          list_del (&alias->node);
          break;
        }
    }
  mutex_unlock (&frida_writable_aliases_mutex);

  mapped_size = (unsigned long) alias->n_pages * PAGE_SIZE;

  vunmap (mapping);

  /* flush_icache_range() inlines a reference to __icache_flags, which GKI does not
   * export; these two are what it would have called. */
  caches_clean_inval_pou (alias->first_page, alias->first_page + mapped_size);
  kick_all_cpus_sync ();

  kfree (alias);
}

static struct page *
frida_page_for_virtual (unsigned long address)
{
  if (frida_is_vmalloc_or_module_addr ((void *) address))
    return vmalloc_to_page ((void *) address);

  if (virt_addr_valid ((void *) address))
    return virt_to_page ((void *) address);

  /*
   * Kernel text and rodata live in the image mapping, which is neither the linear
   * map nor vmalloc space. __pa_symbol() is the sanctioned way out of there.
   */
  return pfn_to_page (__phys_to_pfn (__pa_symbol (address)));
}

/* The kernel's own is_vmalloc_or_module_addr() is not exported, and on arm64 the
 * module region sits below the vmalloc range rather than inside it, so testing for
 * vmalloc alone would miss it. */
static bool
frida_is_vmalloc_or_module_addr (const void * x)
{
#if defined (CONFIG_MODULES) && defined (MODULES_VADDR)
  unsigned long address = (unsigned long) kasan_reset_tag (x);

  if (address >= MODULES_VADDR && address < MODULES_END)
    return true;
#endif

  return is_vmalloc_addr (x);
}

u64
frida_kmod_kernel_base (void)
{
  return frida_kernel_base;
}

u64
frida_kmod_kernel_size (void)
{
  return frida_kernel_size;
}

/*
 * Neither the module list nor the mutex guarding it is exported, so both come
 * from kallsyms. Without them we report nothing rather than walk unsynchronised.
 */
void __nocfi
frida_kmod_enumerate_modules (FridaFoundModuleFunc func,
                              void * user_data)
{
  struct module * mod;

  if (frida_modules == NULL || frida_module_mutex == NULL)
    return;

  mutex_lock (frida_module_mutex);

  list_for_each_entry (mod, frida_modules, list)
    {
      u64 base, size;

      if (mod->state != MODULE_STATE_LIVE)
        continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 4, 0)
      base = (u64) (uintptr_t) mod->mem[MOD_TEXT].base;
      size = mod->mem[MOD_TEXT].size;
#else
      base = (u64) (uintptr_t) mod->core_layout.base;
      size = mod->core_layout.size;
#endif

      if (!func (mod->name, "", base, size, user_data))
        break;
    }

  mutex_unlock (frida_module_mutex);
}

u64
frida_kmod_find_symbol (const char * name)
{
  if (frida_kallsyms_lookup_name_impl == NULL)
    return 0;

  return frida_kallsyms_lookup_name_impl (name);
}

/*
 * sprint_symbol_no_offset() is the only exported reverse lookup. It renders
 * addresses it cannot name as a hex string, which then fails to resolve back to
 * an address, so no separate check for that case is needed.
 */
int
frida_kmod_symbol_name_from_address (u64 address,
                                     char * buffer,
                                     size_t size,
                                     u64 * symbol_address)
{
  char rendered[KSYM_SYMBOL_LEN];
  u64 base;

  sprint_symbol_no_offset (rendered, (unsigned long) address);
  frida_strip_module_suffix (rendered);

  base = frida_kmod_find_symbol (rendered);
  if (base == 0)
    return 0;

  strscpy (buffer, rendered, size);
  *symbol_address = base;

  return 1;
}

static void
frida_strip_module_suffix (char * rendered)
{
  char * suffix = strchr (rendered, ' ');

  if (suffix != NULL)
    *suffix = '\0';
}

int
frida_kmod_enumerate_symbols (FridaFoundSymbolFunc func,
                              void * user_data)
{
  struct frida_symbol_visit_ctx ctx = { func, user_data };

  if (frida_kallsyms_on_each_symbol_impl == NULL)
    return 0;

  frida_kallsyms_on_each_symbol_impl (frida_on_each_symbol, &ctx);

  return 1;
}

/* kallsyms_on_each_symbol() stops when the callback returns non-zero. __nocfi
 * because ctx->func points into the agent, which is not CFI-instrumented. */
static int __nocfi
frida_on_each_symbol (void * data,
                      const char * name,
#if LINUX_VERSION_CODE < KERNEL_VERSION (6, 4, 0)
                      struct module * mod,
#endif
                      unsigned long address)
{
  struct frida_symbol_visit_ctx * ctx = data;

  return ctx->func (name, address, ctx->user_data) ? 0 : 1;
}
