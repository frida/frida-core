#include <linux/completion.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kasan.h>
#include <linux/kfifo.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/wait.h>

#if defined (__has_include)
# if __has_include (<linux/execmem.h>)
#  include <linux/execmem.h>
#  define FRIDA_HAVE_EXECMEM
# endif
#endif

#ifdef CONFIG_X86_64
# include <asm/ibt.h>
#endif
#ifdef CONFIG_ARM64
# include <asm/cacheflush.h>
#endif

#if defined (CONFIG_X86_64)
# define FRIDA_R_ABSOLUTE R_X86_64_64
# define FRIDA_R_RELATIVE R_X86_64_RELATIVE
#elif defined (CONFIG_X86_32)
# define FRIDA_R_ABSOLUTE R_386_32
# define FRIDA_R_RELATIVE R_386_RELATIVE
#elif defined (CONFIG_ARM64)
# define FRIDA_R_ABSOLUTE R_AARCH64_ABS64
# define FRIDA_R_RELATIVE R_AARCH64_RELATIVE
#endif

#define FRIDA_LINK_CAPACITY (1024 * 1024)

#define FRIDA_TRANSPORT_CHARACTER_DEVICE 6

#define FRIDA_SYMBOL_TYPE 0xf
#define FRIDA_SYMBOL_SECTION 0x10

typedef void (* FridaAgentStartFunc) (const void * config, size_t config_size);
typedef void (* FridaAgentNotifyFunc) (void);
#ifdef FRIDA_HAVE_EXECMEM
typedef void * (* FridaExecmemAllocRwFunc) (enum execmem_type type, size_t size);
typedef void (* FridaExecmemFreeFunc) (void * ptr);
#endif

struct frida_agent
{
  u8 * base;
  size_t size;
  size_t text_size;
  FridaAgentStartFunc start;
  FridaAgentNotifyFunc wake;
  FridaAgentNotifyFunc stop;
};

struct frida_elf
{
  const Elf_Ehdr * header;
  const Elf_Shdr * sections;
  const char * section_names;
  const Elf_Sym * symbols;
  unsigned int n_symbols;
  const char * symbol_names;
};

struct frida_loader_export
{
  const char * name;
  void * address;
};

struct frida_kernel_symbol
{
  const char * name;
  u64 offset;
  u32 index;
  u32 entry_offset;
};

struct frida_symbol_census
{
  unsigned int n_symbols;
  size_t name_bytes;
  struct frida_kernel_symbol * symbols;
  char * names;
};

struct frida_config_writer
{
  u8 * data;
  size_t offset;
};

int frida_kmod_link_open (void);
void frida_kmod_link_close (void);
int frida_kmod_link_send (const void * data, size_t size);
long frida_kmod_link_recv (void * data, size_t size);
bool frida_kmod_link_pending (void);
void frida_kmod_exit_worker (void);

static int frida_load_agent (struct frida_agent * agent);
static void frida_unload_agent (struct frida_agent * agent);
static int frida_build_config (const struct frida_agent * agent);
static void frida_start_agent (const struct frida_agent * agent);
static void frida_stop_agent (const struct frida_agent * agent);
static void frida_wake_agent (void);
static int frida_parse_elf (const u8 * image, size_t size, struct frida_elf * elf);
static void frida_copy_segments (const struct frida_elf * elf, struct frida_agent * agent);
static int frida_apply_relocations (const struct frida_elf * elf, struct frida_agent * agent);
static int frida_reject_relocation (unsigned int type);
static void frida_fill_kernel_addresses (const struct frida_elf * elf, struct frida_agent * agent);
static u64 frida_resolve_kernel_address (const char * name);
static void * frida_find_agent_symbol (const struct frida_elf * elf, const struct frida_agent * agent,
    const char * name);
static const Elf_Shdr * frida_find_section (const struct frida_elf * elf, const char * name);
static size_t frida_measure_image (const struct frida_elf * elf);
static size_t frida_measure_text (const struct frida_elf * elf);
static int frida_take_symbol_census (struct frida_symbol_census * census);
static void frida_release_symbol_census (struct frida_symbol_census * census);
static size_t frida_measure_symbol_table (const struct frida_symbol_census * census);
static void frida_write_symbol_table (struct frida_symbol_census * census, u8 * table);
static void frida_store_u16 (u8 * destination, u16 value);
static void frida_store_u32 (u8 * destination, u32 value);
static void frida_store_u64 (u8 * destination, u64 value);
static int frida_compare_symbol_names (const void * a, const void * b);
static int frida_compare_symbol_offsets (const void * a, const void * b);
static size_t frida_measure_config (size_t symbol_table_size, unsigned int * offset_size);
static void frida_write_modules (struct frida_config_writer * writer);
static void frida_write_u8 (struct frida_config_writer * writer, u8 value);
static void frida_write_u64 (struct frida_config_writer * writer, u64 value);
static void frida_write_bytes (struct frida_config_writer * writer, const void * data, size_t size);
static void frida_write_offset (struct frida_config_writer * writer, size_t value, unsigned int size);
static void frida_align_writer (struct frida_config_writer * writer, size_t alignment);
static unsigned int frida_framing_offset_size (size_t body_size, unsigned int n_offsets);
static void frida_resolve_kallsyms (void);
static void frida_resolve_kernel_range (void);
static void frida_resolve_memory_protection (void);
static void frida_resolve_code_allocator (void);
static void * frida_resolve_unexported (const char * name);
static void * frida_rewind_to_function_entry (void * address);
static void * frida_unseal_landing_pad (void * address);
static bool frida_is_kernel_text (u64 address);
static void * frida_alloc_code (size_t size);
static void frida_free_code (void * ptr);
static void frida_protect_text (const struct frida_agent * agent);
static void frida_unprotect_text (const struct frida_agent * agent);
static int frida_dev_open (struct inode * inode, struct file * file);
static int frida_dev_release (struct inode * inode, struct file * file);
static ssize_t frida_dev_read (struct file * file, char __user * buffer, size_t size,
    loff_t * offset);
static ssize_t frida_dev_write (struct file * file, const char __user * buffer, size_t size,
    loff_t * offset);
static __poll_t frida_dev_poll (struct file * file, struct poll_table_struct * wait);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 4, 0)
static int frida_count_symbol (void * data, const char * name, unsigned long address);
static int frida_record_symbol (void * data, const char * name, unsigned long address);
#else
static int frida_count_symbol (void * data, const char * name, struct module * mod,
    unsigned long address);
static int frida_record_symbol (void * data, const char * name, struct module * mod,
    unsigned long address);
#endif

extern const u8 frida_agent_image_start[];
extern const u8 frida_agent_image_end[];

static const struct frida_loader_export frida_loader_exports[] =
{
  { "frida_kmod_link_open", frida_kmod_link_open },
  { "frida_kmod_link_close", frida_kmod_link_close },
  { "frida_kmod_link_send", frida_kmod_link_send },
  { "frida_kmod_link_recv", frida_kmod_link_recv },
  { "frida_kmod_link_pending", frida_kmod_link_pending },
  { "frida_kmod_exit_worker", frida_kmod_exit_worker },
};

static struct frida_agent frida_agent;
static u8 * frida_config;
static size_t frida_config_size;
static DECLARE_COMPLETION (frida_worker_done);

static u64 frida_kernel_base;
static u64 frida_kernel_size;
static u64 frida_text_start;
static u64 frida_text_end;

static typeof (&kallsyms_lookup_name) frida_kallsyms_lookup_name_impl;
static typeof (&kallsyms_on_each_symbol) frida_kallsyms_on_each_symbol_impl;
static typeof (&set_memory_ro) frida_set_memory_ro_impl;
static typeof (&set_memory_rw) frida_set_memory_rw_impl;
static typeof (&set_memory_x) frida_set_memory_x_impl;
static typeof (&set_memory_nx) frida_set_memory_nx_impl;
#ifdef FRIDA_HAVE_EXECMEM
static FridaExecmemAllocRwFunc frida_execmem_alloc_rw_impl;
static FridaExecmemFreeFunc frida_execmem_free_impl;
#endif

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
  int res;

  frida_resolve_kallsyms ();
  if (frida_kallsyms_lookup_name_impl == NULL || frida_kallsyms_on_each_symbol_impl == NULL)
    return -ENOENT;
  frida_resolve_kernel_range ();
  frida_resolve_memory_protection ();
  frida_resolve_code_allocator ();

  res = frida_load_agent (&frida_agent);
  if (res != 0)
    return res;

  res = frida_build_config (&frida_agent);
  if (res != 0)
    {
      frida_unload_agent (&frida_agent);
      return res;
    }

  frida_start_agent (&frida_agent);

  return 0;
}

static void __exit
frida_kmod_exit (void)
{
  frida_stop_agent (&frida_agent);
  wait_for_completion (&frida_worker_done);

  frida_kmod_link_close ();
  frida_unload_agent (&frida_agent);
  kvfree (frida_config);
}

module_init (frida_kmod_init);
module_exit (frida_kmod_exit);

MODULE_LICENSE ("GPL");
MODULE_DESCRIPTION ("Frida instrumentation agent");
MODULE_VERSION ("1.0.0");

static int
frida_load_agent (struct frida_agent * agent)
{
  struct frida_elf elf;
  int res;

  res = frida_parse_elf (frida_agent_image_start, frida_agent_image_end - frida_agent_image_start, &elf);
  if (res != 0)
    return res;

  agent->size = PAGE_ALIGN (frida_measure_image (&elf));
  agent->text_size = PAGE_ALIGN (frida_measure_text (&elf));
  agent->base = frida_alloc_code (agent->size);
  if (agent->base == NULL)
    return -ENOMEM;
  memset (agent->base, 0, agent->size);

  frida_copy_segments (&elf, agent);

  res = frida_apply_relocations (&elf, agent);
  if (res != 0)
    goto failure;

  frida_fill_kernel_addresses (&elf, agent);

  agent->start = frida_find_agent_symbol (&elf, agent, "_start");
  agent->wake = frida_find_agent_symbol (&elf, agent, "frida_agent_wake");
  agent->stop = frida_find_agent_symbol (&elf, agent, "frida_agent_stop");
  if (agent->start == NULL || agent->wake == NULL || agent->stop == NULL)
    {
      res = -ENOEXEC;
      goto failure;
    }

  frida_protect_text (agent);

  return 0;

failure:
  frida_free_code (agent->base);
  agent->base = NULL;

  return res;
}

static void
frida_unload_agent (struct frida_agent * agent)
{
  frida_unprotect_text (agent);
  frida_free_code (agent->base);
  agent->base = NULL;
}

static int
frida_build_config (const struct frida_agent * agent)
{
  struct frida_symbol_census census;
  size_t symbol_table_size, transport_end, modules_end, symbols_end, notes_end;
  unsigned int offset_size;
  struct frida_config_writer writer;
  int res;

  res = frida_take_symbol_census (&census);
  if (res != 0)
    return res;

  symbol_table_size = frida_measure_symbol_table (&census);
  frida_config_size = frida_measure_config (symbol_table_size, &offset_size);
  frida_config = kvzalloc (frida_config_size, GFP_KERNEL);
  if (frida_config == NULL)
    {
      frida_release_symbol_census (&census);
      return -ENOMEM;
    }

  writer.data = frida_config;
  writer.offset = 0;

  frida_write_u64 (&writer, (u64) (uintptr_t) agent->base);
  frida_write_u64 (&writer, agent->size);
  frida_write_u8 (&writer, FRIDA_TRANSPORT_CHARACTER_DEVICE);
  frida_align_writer (&writer, 8);
  frida_write_bytes (&writer, "\0\0()", 4);
  transport_end = writer.offset;
  frida_align_writer (&writer, 8);
  frida_write_u64 (&writer, frida_kernel_base);
  frida_align_writer (&writer, 8);
  frida_write_modules (&writer);
  modules_end = writer.offset;
  frida_write_symbol_table (&census, writer.data + writer.offset);
  writer.offset += symbol_table_size;
  symbols_end = writer.offset;
  frida_align_writer (&writer, 8);
  notes_end = writer.offset;
  frida_align_writer (&writer, 8);

  frida_write_offset (&writer, notes_end, offset_size);
  frida_write_offset (&writer, symbols_end, offset_size);
  frida_write_offset (&writer, modules_end, offset_size);
  frida_write_offset (&writer, transport_end, offset_size);

  frida_release_symbol_census (&census);

  return 0;
}

static void __nocfi
frida_start_agent (const struct frida_agent * agent)
{
  agent->start (frida_config, frida_config_size);
}

static void __nocfi
frida_stop_agent (const struct frida_agent * agent)
{
  agent->stop ();
}

static void __nocfi
frida_wake_agent (void)
{
  frida_agent.wake ();
}

static int
frida_parse_elf (const u8 * image,
                 size_t size,
                 struct frida_elf * elf)
{
  const Elf_Shdr * symtab = NULL;
  unsigned int i;

  if (size < sizeof (Elf_Ehdr) || memcmp (image, ELFMAG, SELFMAG) != 0)
    return -ENOEXEC;

  elf->header = (const Elf_Ehdr *) image;
  elf->sections = (const Elf_Shdr *) (image + elf->header->e_shoff);
  elf->section_names = (const char *) (image + elf->sections[elf->header->e_shstrndx].sh_offset);

  for (i = 0; i != elf->header->e_shnum; i++)
    {
      if (elf->sections[i].sh_type == SHT_SYMTAB)
        {
          symtab = &elf->sections[i];
          break;
        }
    }
  if (symtab == NULL)
    return -ENOEXEC;

  elf->symbols = (const Elf_Sym *) (image + symtab->sh_offset);
  elf->n_symbols = symtab->sh_size / sizeof (Elf_Sym);
  elf->symbol_names = (const char *) (image + elf->sections[symtab->sh_link].sh_offset);

  return 0;
}

static void
frida_copy_segments (const struct frida_elf * elf,
                     struct frida_agent * agent)
{
  const Elf_Phdr * segments = (const Elf_Phdr *) ((const u8 *) elf->header + elf->header->e_phoff);
  unsigned int i;

  for (i = 0; i != elf->header->e_phnum; i++)
    {
      const Elf_Phdr * segment = &segments[i];

      if (segment->p_type != PT_LOAD)
        continue;

      memcpy (agent->base + segment->p_vaddr, (const u8 *) elf->header + segment->p_offset,
          segment->p_filesz);
    }
}

#ifdef CONFIG_MODULES_USE_ELF_RELA

static int
frida_apply_relocations (const struct frida_elf * elf,
                         struct frida_agent * agent)
{
  const Elf_Shdr * section;
  const Elf_Rela * relocations;
  unsigned int n_relocations, i;

  section = frida_find_section (elf, ".rela.dyn");
  if (section == NULL)
    return 0;

  relocations = (const Elf_Rela *) ((const u8 *) elf->header + section->sh_offset);
  n_relocations = section->sh_size / sizeof (Elf_Rela);

  for (i = 0; i != n_relocations; i++)
    {
      const Elf_Rela * r = &relocations[i];
      unsigned long * slot = (unsigned long *) (agent->base + r->r_offset);

      switch (ELF_R_TYPE (r->r_info))
        {
        case FRIDA_R_RELATIVE:
          *slot = (unsigned long) agent->base + r->r_addend;
          break;
        case FRIDA_R_ABSOLUTE:
          *slot += (unsigned long) agent->base;
          break;
        default:
          return frida_reject_relocation (ELF_R_TYPE (r->r_info));
        }
    }

  return 0;
}

#else

static int
frida_apply_relocations (const struct frida_elf * elf,
                         struct frida_agent * agent)
{
  const Elf_Shdr * section;
  const Elf_Rel * relocations;
  unsigned int n_relocations, i;

  section = frida_find_section (elf, ".rel.dyn");
  if (section == NULL)
    return 0;

  relocations = (const Elf_Rel *) ((const u8 *) elf->header + section->sh_offset);
  n_relocations = section->sh_size / sizeof (Elf_Rel);

  for (i = 0; i != n_relocations; i++)
    {
      const Elf_Rel * r = &relocations[i];
      unsigned long * slot = (unsigned long *) (agent->base + r->r_offset);

      switch (ELF_R_TYPE (r->r_info))
        {
        case FRIDA_R_RELATIVE:
        case FRIDA_R_ABSOLUTE:
          *slot += (unsigned long) agent->base;
          break;
        default:
          return frida_reject_relocation (ELF_R_TYPE (r->r_info));
        }
    }

  return 0;
}

#endif

static int
frida_reject_relocation (unsigned int type)
{
  printk (KERN_ERR "frida: unsupported relocation type %u\n", type);

  return -ENOEXEC;
}

static void
frida_fill_kernel_addresses (const struct frida_elf * elf,
                             struct frida_agent * agent)
{
  const Elf_Shdr * section;
  unsigned int section_index, i;

  section = frida_find_section (elf, ".kernel_addrs");
  if (section == NULL)
    return;
  section_index = section - elf->sections;

  for (i = 0; i != elf->n_symbols; i++)
    {
      const Elf_Sym * symbol = &elf->symbols[i];
      const char * name = elf->symbol_names + symbol->st_name;

      if (symbol->st_shndx != section_index || name[0] != '_')
        continue;

      *(unsigned long *) (agent->base + symbol->st_value) = frida_resolve_kernel_address (name + 1);
    }
}

static u64
frida_resolve_kernel_address (const char * name)
{
  unsigned int i;
  u64 address;

  for (i = 0; i != ARRAY_SIZE (frida_loader_exports); i++)
    {
      if (strcmp (frida_loader_exports[i].name, name) == 0)
        return (u64) (uintptr_t) frida_loader_exports[i].address;
    }

  address = frida_kallsyms_lookup_name_impl (name);
  if (frida_is_kernel_text (address))
    return (u64) (uintptr_t) frida_unseal_landing_pad ((void *) (uintptr_t) address);

  return address;
}

static void *
frida_find_agent_symbol (const struct frida_elf * elf,
                         const struct frida_agent * agent,
                         const char * name)
{
  unsigned int i;

  for (i = 0; i != elf->n_symbols; i++)
    {
      const Elf_Sym * symbol = &elf->symbols[i];

      if (symbol->st_shndx != SHN_UNDEF && strcmp (elf->symbol_names + symbol->st_name, name) == 0)
        return agent->base + symbol->st_value;
    }

  return NULL;
}

static const Elf_Shdr *
frida_find_section (const struct frida_elf * elf,
                    const char * name)
{
  unsigned int i;

  for (i = 0; i != elf->header->e_shnum; i++)
    {
      if (strcmp (elf->section_names + elf->sections[i].sh_name, name) == 0)
        return &elf->sections[i];
    }

  return NULL;
}

static size_t
frida_measure_image (const struct frida_elf * elf)
{
  const Elf_Phdr * segments = (const Elf_Phdr *) ((const u8 *) elf->header + elf->header->e_phoff);
  size_t end = 0;
  unsigned int i;

  for (i = 0; i != elf->header->e_phnum; i++)
    {
      if (segments[i].p_type == PT_LOAD)
        end = max_t (size_t, end, segments[i].p_vaddr + segments[i].p_memsz);
    }

  return end;
}

static size_t
frida_measure_text (const struct frida_elf * elf)
{
  const Elf_Phdr * segments = (const Elf_Phdr *) ((const u8 *) elf->header + elf->header->e_phoff);
  unsigned int i;

  for (i = 0; i != elf->header->e_phnum; i++)
    {
      if (segments[i].p_type == PT_LOAD && (segments[i].p_flags & PF_X) != 0)
        return segments[i].p_vaddr + segments[i].p_memsz;
    }

  return 0;
}

static int
frida_take_symbol_census (struct frida_symbol_census * census)
{
  census->n_symbols = 0;
  census->name_bytes = 0;
  frida_kallsyms_on_each_symbol_impl (frida_count_symbol, census);

  census->symbols = kvmalloc_array (census->n_symbols, sizeof (struct frida_kernel_symbol), GFP_KERNEL);
  census->names = kvmalloc (census->name_bytes, GFP_KERNEL);
  if (census->symbols == NULL || census->names == NULL)
    {
      frida_release_symbol_census (census);
      return -ENOMEM;
    }

  census->n_symbols = 0;
  census->name_bytes = 0;
  frida_kallsyms_on_each_symbol_impl (frida_record_symbol, census);

  return 0;
}

static void
frida_release_symbol_census (struct frida_symbol_census * census)
{
  kvfree (census->symbols);
  kvfree (census->names);
}

static size_t
frida_measure_symbol_table (const struct frida_symbol_census * census)
{
  size_t size;
  unsigned int i;

  size = sizeof (u32) + 2 * census->n_symbols * sizeof (u32);
  for (i = 0; i != census->n_symbols; i++)
    size = ALIGN (size, 8) + sizeof (u64) + 2 * sizeof (u8) + sizeof (u16)
        + strlen (census->symbols[i].name) + 1;

  return size;
}

static void
frida_write_symbol_table (struct frida_symbol_census * census,
                          u8 * table)
{
  u8 * name_index, * address_index;
  size_t offset;
  unsigned int i;

  sort (census->symbols, census->n_symbols, sizeof (struct frida_kernel_symbol),
      frida_compare_symbol_names, NULL);

  frida_store_u32 (table, census->n_symbols);
  name_index = table + sizeof (u32);
  address_index = name_index + census->n_symbols * sizeof (u32);

  offset = sizeof (u32) + 2 * census->n_symbols * sizeof (u32);
  for (i = 0; i != census->n_symbols; i++)
    {
      struct frida_kernel_symbol * symbol = &census->symbols[i];
      size_t name_size = strlen (symbol->name) + 1;
      u8 * entry;

      offset = ALIGN (offset, 8);
      entry = table + offset;
      symbol->entry_offset = offset;
      frida_store_u32 (name_index + i * sizeof (u32), offset);

      frida_store_u64 (entry, symbol->offset);
      entry[8] = FRIDA_SYMBOL_TYPE;
      entry[9] = FRIDA_SYMBOL_SECTION;
      frida_store_u16 (entry + 10, 0);
      memcpy (entry + 12, symbol->name, name_size);

      offset += 12 + name_size;
    }

  sort (census->symbols, census->n_symbols, sizeof (struct frida_kernel_symbol),
      frida_compare_symbol_offsets, NULL);

  for (i = 0; i != census->n_symbols; i++)
    frida_store_u32 (address_index + i * sizeof (u32), census->symbols[i].entry_offset);
}

static void
frida_store_u16 (u8 * destination,
                 u16 value)
{
  __le16 encoded = cpu_to_le16 (value);

  memcpy (destination, &encoded, sizeof (encoded));
}

static void
frida_store_u32 (u8 * destination,
                 u32 value)
{
  __le32 encoded = cpu_to_le32 (value);

  memcpy (destination, &encoded, sizeof (encoded));
}

static void
frida_store_u64 (u8 * destination,
                 u64 value)
{
  __le64 encoded = cpu_to_le64 (value);

  memcpy (destination, &encoded, sizeof (encoded));
}

static int
frida_compare_symbol_names (const void * a,
                            const void * b)
{
  const struct frida_kernel_symbol * x = a;
  const struct frida_kernel_symbol * y = b;
  int res;

  res = strcmp (x->name, y->name);
  if (res != 0)
    return res;

  return (x->index > y->index) - (x->index < y->index);
}

static int
frida_compare_symbol_offsets (const void * a,
                              const void * b)
{
  const struct frida_kernel_symbol * x = a;
  const struct frida_kernel_symbol * y = b;

  if (x->offset != y->offset)
    return (x->offset > y->offset) ? 1 : -1;

  return (x->index > y->index) - (x->index < y->index);
}

static size_t
frida_measure_config (size_t symbol_table_size,
                      unsigned int * offset_size)
{
  struct frida_config_writer probe = { NULL, 0 };
  size_t body_size;

  probe.offset = 2 * sizeof (u64) + sizeof (u8);
  frida_align_writer (&probe, 8);
  probe.offset += 4;
  frida_align_writer (&probe, 8);
  probe.offset += sizeof (u64);
  frida_align_writer (&probe, 8);
  frida_write_modules (&probe);
  probe.offset += symbol_table_size;
  frida_align_writer (&probe, 8);
  frida_align_writer (&probe, 8);
  body_size = probe.offset;

  *offset_size = frida_framing_offset_size (body_size, 4);

  return body_size + 4 * *offset_size;
}

static void
frida_write_modules (struct frida_config_writer * writer)
{
  static const char element_strings[] = "kernel\0";
  const size_t name_end = 7, version_end = 8, element_size = 8 + 4 * sizeof (u64) + 2;
  struct frida_config_writer element;

  if (writer->data != NULL)
    {
      element.data = writer->data + writer->offset;
      element.offset = 0;

      frida_write_bytes (&element, element_strings, sizeof (element_strings));
      frida_write_u64 (&element, 0);
      frida_write_u64 (&element, frida_kernel_size);
      frida_write_u64 (&element, 0);
      frida_write_u64 (&element, 0);
      frida_write_offset (&element, version_end, 1);
      frida_write_offset (&element, name_end, 1);
      frida_write_offset (&element, element_size, 1);
    }

  writer->offset += element_size + 1;
}

static void
frida_write_u8 (struct frida_config_writer * writer,
                u8 value)
{
  frida_write_bytes (writer, &value, sizeof (value));
}

static void
frida_write_u64 (struct frida_config_writer * writer,
                 u64 value)
{
  __le64 encoded = cpu_to_le64 (value);

  frida_write_bytes (writer, &encoded, sizeof (encoded));
}

static void
frida_write_bytes (struct frida_config_writer * writer,
                   const void * data,
                   size_t size)
{
  memcpy (writer->data + writer->offset, data, size);
  writer->offset += size;
}

static void
frida_write_offset (struct frida_config_writer * writer,
                    size_t value,
                    unsigned int size)
{
  __le64 encoded = cpu_to_le64 (value);

  frida_write_bytes (writer, &encoded, size);
}

static void
frida_align_writer (struct frida_config_writer * writer,
                    size_t alignment)
{
  writer->offset = ALIGN (writer->offset, alignment);
}

static unsigned int
frida_framing_offset_size (size_t body_size,
                           unsigned int n_offsets)
{
  if (body_size + n_offsets <= U8_MAX)
    return 1;
  if (body_size + 2 * n_offsets <= U16_MAX)
    return 2;
  if (body_size + 4 * n_offsets <= U32_MAX)
    return 4;
  return 8;
}

static void
frida_resolve_kallsyms (void)
{
  frida_kallsyms_lookup_name_impl = frida_resolve_unexported ("kallsyms_lookup_name");
  frida_kallsyms_on_each_symbol_impl = frida_resolve_unexported ("kallsyms_on_each_symbol");

  if (frida_kallsyms_lookup_name_impl == NULL)
    printk (KERN_WARNING "frida: kallsyms_lookup_name unavailable\n");
}

static void
frida_resolve_kernel_range (void)
{
  frida_kernel_base = frida_kallsyms_lookup_name_impl ("_text");
  frida_kernel_size = frida_kallsyms_lookup_name_impl ("_end") - frida_kernel_base;
  frida_text_start = frida_kallsyms_lookup_name_impl ("_stext");
  frida_text_end = frida_kallsyms_lookup_name_impl ("_etext");
}

static void
frida_resolve_memory_protection (void)
{
  /*
   * GKI trims its export table to the KMI symbol list, which leaves set_memory_*()
   * callable but unexported. Being absent from Module.symvers only stops the module
   * loader from resolving them, so go through kallsyms like everything else here.
   */
  frida_set_memory_ro_impl = (void *) frida_resolve_kernel_address ("set_memory_ro");
  frida_set_memory_rw_impl = (void *) frida_resolve_kernel_address ("set_memory_rw");
  frida_set_memory_x_impl = (void *) frida_resolve_kernel_address ("set_memory_x");
  frida_set_memory_nx_impl = (void *) frida_resolve_kernel_address ("set_memory_nx");
}

static void
frida_resolve_code_allocator (void)
{
#ifdef FRIDA_HAVE_EXECMEM
  FridaExecmemAllocRwFunc alloc_rw;
  FridaExecmemFreeFunc free;

  alloc_rw = (FridaExecmemAllocRwFunc) frida_resolve_kernel_address ("execmem_alloc_rw");
  free = (FridaExecmemFreeFunc) frida_resolve_kernel_address ("execmem_free");
  if (alloc_rw == NULL || free == NULL)
    return;

  frida_execmem_alloc_rw_impl = alloc_rw;
  frida_execmem_free_impl = free;
#endif
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

  return frida_unseal_landing_pad (frida_rewind_to_function_entry (address));
}

static void *
frida_rewind_to_function_entry (void * address)
{
#ifdef HAS_KERNEL_IBT
  u32 * pad = (u32 *) ((u8 *) address - ENDBR_INSN_SIZE);

  if (*pad == gen_endbr () || *pad == gen_endbr_poison ())
    return pad;
#endif

  return address;
}

static void *
frida_unseal_landing_pad (void * address)
{
#ifdef HAS_KERNEL_IBT
  unsigned long first_page = (unsigned long) address & PAGE_MASK;
  unsigned int n_pages = ((((unsigned long) address + ENDBR_INSN_SIZE - 1) & PAGE_MASK)
      - first_page) / PAGE_SIZE + 1;
  struct page * pages[2];
  unsigned int i;
  u8 * alias;

  if (*(u32 *) address != gen_endbr_poison ())
    return address;

  for (i = 0; i != n_pages; i++)
    pages[i] = pfn_to_page (__phys_to_pfn (__pa_symbol (first_page + i * PAGE_SIZE)));

  alias = vmap (pages, n_pages, VM_MAP, PAGE_KERNEL);
  if (alias == NULL)
    return address;

  *(u32 *) (alias + ((unsigned long) address - first_page)) = gen_endbr ();

  vunmap (alias);
  kick_all_cpus_sync ();
#endif

  return address;
}

static bool
frida_is_kernel_text (u64 address)
{
  return address >= frida_text_start && address < frida_text_end;
}

static void *
frida_alloc_code (size_t size)
{
#ifdef FRIDA_HAVE_EXECMEM
  if (frida_execmem_alloc_rw_impl != NULL)
    return frida_execmem_alloc_rw_impl (EXECMEM_MODULE_TEXT, size);
#endif

  return __vmalloc (size, GFP_KERNEL);
}

static void
frida_free_code (void * ptr)
{
#ifdef FRIDA_HAVE_EXECMEM
  if (frida_execmem_alloc_rw_impl != NULL)
    {
      frida_execmem_free_impl (ptr);
      return;
    }
#endif

  vfree (ptr);
}

static void
frida_protect_text (const struct frida_agent * agent)
{
  unsigned long start = (unsigned long) agent->base;
  int n_pages = agent->text_size / PAGE_SIZE;

  frida_set_memory_ro_impl (start, n_pages);
  frida_set_memory_x_impl (start, n_pages);
#ifdef CONFIG_ARM64
  caches_clean_inval_pou (start, start + agent->text_size);
#endif
}

static void
frida_unprotect_text (const struct frida_agent * agent)
{
  unsigned long start = (unsigned long) agent->base;
  int n_pages = agent->text_size / PAGE_SIZE;

  frida_set_memory_nx_impl (start, n_pages);
  frida_set_memory_rw_impl (start, n_pages);
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

bool
frida_kmod_link_pending (void)
{
  return !kfifo_is_empty (&frida_from_client);
}

void
frida_kmod_exit_worker (void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION (5, 17, 0)
  kthread_complete_and_exit (&frida_worker_done, 0);
#else
  complete_and_exit (&frida_worker_done, 0);
#endif
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

  frida_wake_agent ();

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

static int
frida_count_symbol (void * data,
                    const char * name,
#if LINUX_VERSION_CODE < KERNEL_VERSION (6, 4, 0)
                    struct module * mod,
#endif
                    unsigned long address)
{
  struct frida_symbol_census * census = data;

#if LINUX_VERSION_CODE < KERNEL_VERSION (6, 4, 0)
  if (mod != NULL)
    return 0;
#endif

  census->n_symbols++;
  census->name_bytes += strlen (name) + 1;

  return 0;
}

static int
frida_record_symbol (void * data,
                     const char * name,
#if LINUX_VERSION_CODE < KERNEL_VERSION (6, 4, 0)
                     struct module * mod,
#endif
                     unsigned long address)
{
  struct frida_symbol_census * census = data;
  struct frida_kernel_symbol * symbol;
  size_t name_size = strlen (name) + 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION (6, 4, 0)
  if (mod != NULL)
    return 0;
#endif

  symbol = &census->symbols[census->n_symbols];
  symbol->name = census->names + census->name_bytes;
  symbol->offset = (address >= frida_kernel_base) ? address - frida_kernel_base : address;
  symbol->index = census->n_symbols;
  memcpy (census->names + census->name_bytes, name, name_size);

  census->n_symbols++;
  census->name_bytes += name_size;

  return 0;
}
