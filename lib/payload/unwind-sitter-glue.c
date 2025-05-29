#include "frida-payload.h"

#ifdef HAVE_DARWIN

#include <capstone.h>
#include <gum/gumdarwin.h>
#include <gum/gummemory.h>
#include <ptrauth.h>

#define FRIDA_MH_MAGIC_64 0xfeedfacf
#define FRIDA_LIBUNWIND_PATH "/usr/lib/system/libunwind.dylib"
#define FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO 0x68
#define FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG 0x18
#define FRIDA_FP_TO_SP(fp) (fp + 0x10)
#ifdef HAVE_ARM64
# define FRIDA_UNWIND_CURSOR_unwindInfoMissing 0x268
# define FRIDA_UNWAARCH64_X29 29
# define FRIDA_STRIP_MASK 0x0000007fffffffffULL
#else
# define FRIDA_UNWIND_CURSOR_unwindInfoMissing 0x100
# define FRIDA_UNWX86_64_RBP 6
#endif

typedef struct _FridaFillInfoContext FridaFillInfoContext;
typedef struct _FridaDyldUnwindSections FridaDyldUnwindSections;
typedef struct _FridaCreateArgs FridaCreateArgs;
typedef struct _FridaUnwindHookState FridaUnwindHookState;

struct _FridaFillInfoContext
{
  FridaDyldUnwindSections * info;
  guint missing_info;
};

struct _FridaDyldUnwindSections
{
  const void * mh;
  const void * dwarf_section;
  uintptr_t dwarf_section_length;
  const void * compact_unwind_section;
  uintptr_t compact_unwind_section_length;
};

struct _FridaCreateArgs
{
  GumAddress range_start;
  GumAddress range_end;
};

struct _FridaUnwindHookState
{
  gpointer vtable;
  gssize shift;
  gpointer * set_info_slot;
  gpointer set_info_original;
  void (* set_info) (gpointer cursor, gint is_return_address);
  gpointer (* get_reg) (gpointer cursor, gint reg);
  GumInterceptor * interceptor;
};

#if __has_feature (ptrauth_calls)
# define FRIDA_RESIGN_PTR(x) GSIZE_TO_POINTER (gum_sign_code_address (gum_strip_code_address (GUM_ADDRESS (x))))
#else
# define FRIDA_RESIGN_PTR(x) (x)
#endif

static FridaDyldUnwindSections * frida_get_cached_sections (GumAddress range_start, GumAddress range_end);
static FridaDyldUnwindSections * frida_create_cached_sections (FridaCreateArgs * args);
static gboolean frida_fill_info (const GumDarwinSectionDetails * details, FridaFillInfoContext * ctx);
static void frida_unwind_cursor_set_info_replacement (gpointer cursor, gint is_return_address);
static gpointer frida_find_vtable (void);
static gboolean frida_compute_vtable_shift (gpointer vtable, gssize * shift);
#ifdef HAVE_ARM64
static gboolean frida_find_bss_range (const GumSectionDetails * details, GumMemoryRange * range);
#else
static gboolean frida_is_empty_function (GumAddress address);
static gboolean frida_has_first_match (GumAddress address, gsize size, gboolean * matches);
#endif

static FridaUnwindHookState * state = NULL;

void
_frida_unwind_sitter_fill_unwind_sections (GumAddress invader_start, GumAddress invader_end, void * info)
{
  FridaDyldUnwindSections * unwind_sections = info;
  FridaDyldUnwindSections * cached;

  cached = frida_get_cached_sections (invader_start, invader_end);
  if (cached == NULL)
    return;

  memcpy (unwind_sections, cached, sizeof (FridaDyldUnwindSections));
}

void
_frida_unwind_sitter_hook_libunwind (void)
{
#if GLIB_SIZEOF_VOID_P == 8
  gpointer * set_info_slot;
  gpointer get_reg_impl;

  if (state != NULL)
    return;

  state = g_slice_new0 (FridaUnwindHookState);
  if (state == NULL)
    return;

  state->vtable = frida_find_vtable ();
  if (state->vtable == NULL)
    goto unsupported_version;

  if (!frida_compute_vtable_shift (state->vtable, &state->shift))
    goto unsupported_version;

  set_info_slot = (gpointer *) (GUM_ADDRESS (state->vtable) + FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO + state->shift);
  get_reg_impl = *(gpointer *) (GUM_ADDRESS (state->vtable) + FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG + state->shift);

  state->set_info_slot = set_info_slot;
  state->set_info_original = *set_info_slot;
  state->set_info = FRIDA_RESIGN_PTR (state->set_info_original);
  state->get_reg = FRIDA_RESIGN_PTR (get_reg_impl);

  state->interceptor = gum_interceptor_obtain ();

  if (gum_interceptor_replace (state->interceptor, state->set_info_original, frida_unwind_cursor_set_info_replacement, NULL, NULL)
      != GUM_REPLACE_OK)
    goto unsupported_version;

  return;

unsupported_version:
  g_slice_free (FridaUnwindHookState, state);
  state = NULL;
#endif
}

void
_frida_unwind_sitter_unhook_libunwind (void)
{
  if (state == NULL)
    return;

  gum_interceptor_revert (state->interceptor, state->set_info_original);

  g_object_unref (state->interceptor);

  g_slice_free (FridaUnwindHookState, state);
  state = NULL;
}

static FridaDyldUnwindSections *
frida_get_cached_sections (GumAddress range_start, GumAddress range_end)
{
  static GOnce get_sections_once = G_ONCE_INIT;
  FridaCreateArgs args;

  args.range_start = range_start;
  args.range_end = range_end;

  g_once (&get_sections_once, (GThreadFunc) frida_create_cached_sections, &args);

  return (FridaDyldUnwindSections *) get_sections_once.retval;
}

static FridaDyldUnwindSections *
frida_create_cached_sections (FridaCreateArgs * args)
{
  FridaDyldUnwindSections * cached_sections;
  gsize page_size;
  gpointer header;
  GumPageProtection prot;
  GumDarwinModule * module;
  FridaFillInfoContext ctx;

  page_size = gum_query_page_size ();
  header = GSIZE_TO_POINTER (args->range_start);

  while ((gum_memory_query_protection (header, &prot) && (prot & GUM_PAGE_READ) == 0) ||
      (*(guint32 *) header != FRIDA_MH_MAGIC_64 && header + 4 <= GSIZE_TO_POINTER (args->range_end)))
  {
    header += page_size;
  }
  if (*(guint32 *) header != FRIDA_MH_MAGIC_64)
    return NULL;

  cached_sections = g_slice_new0 (FridaDyldUnwindSections);
  cached_sections->mh = header;

  module = gum_darwin_module_new_from_memory ("Frida", mach_task_self (), GPOINTER_TO_SIZE (header), GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  if (module == NULL)
    return cached_sections;

  ctx.info = cached_sections;
  ctx.missing_info = 2;
  gum_darwin_module_enumerate_sections (module, (GumFoundDarwinSectionFunc) frida_fill_info, &ctx);

  g_object_unref (module);

  return cached_sections;
}

static gboolean
frida_fill_info (const GumDarwinSectionDetails * details, FridaFillInfoContext * ctx)
{
  if (strcmp ("__TEXT", details->segment_name) != 0)
    return TRUE;

  if (strcmp ("__eh_frame", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->dwarf_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->dwarf_section_length = details->size;
  }
  else if (strcmp ("__unwind_info", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->compact_unwind_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->compact_unwind_section_length = details->size;
  }

  return ctx->missing_info > 0;
}

static void
frida_unwind_cursor_set_info_replacement (gpointer self, gint is_return_address)
{
  gboolean missing_info;
  GumAddress fp, stored_pc;
  gpointer * stored_pc_slot;
#if defined (HAVE_ARM64) && !__has_feature (ptrauth_calls)
  gboolean was_signed = FALSE;
#endif

  if (state == NULL)
    return;

  state->set_info (self, is_return_address);

#ifdef HAVE_ARM64
  fp = GUM_ADDRESS (state->get_reg (self, FRIDA_UNWAARCH64_X29));
#else
  fp = GUM_ADDRESS (state->get_reg (self, FRIDA_UNWX86_64_RBP));
#endif
  if (fp == 0 || fp == -1)
    return;

  missing_info = *((guint8 *) self + FRIDA_UNWIND_CURSOR_unwindInfoMissing);

  stored_pc_slot = GSIZE_TO_POINTER (fp + GLIB_SIZEOF_VOID_P);
  stored_pc = GUM_ADDRESS (*stored_pc_slot);
#if __has_feature (ptrauth_calls)
  stored_pc = gum_strip_code_address (stored_pc);
#elif defined (HAVE_ARM64)
  was_signed = (stored_pc & ~FRIDA_STRIP_MASK) != 0ULL;
  if (was_signed)
    stored_pc &= FRIDA_STRIP_MASK;
#endif

  if (!missing_info)
  {
    GumAddress translated;

    translated = GUM_ADDRESS (gum_invocation_stack_translate (gum_interceptor_get_current_stack (), GSIZE_TO_POINTER (stored_pc)));
    if (translated != stored_pc)
    {
#if __has_feature (ptrauth_calls)
      *stored_pc_slot = ptrauth_sign_unauthenticated (
          ptrauth_strip (GSIZE_TO_POINTER (translated), ptrauth_key_asia), ptrauth_key_asib, FRIDA_FP_TO_SP (fp));
#elif defined (HAVE_ARM64)
      if (was_signed)
      {
        GumAddress resigned;

        asm volatile (
            "mov x17, %1\n\t"
            "mov x16, %2\n\t"
            ".byte 0x5f, 0x21, 0x03, 0xd5\n\t" /* pacib1716 */
            "mov %0, x17\n\t"
            : "=r" (resigned)
            : "r" (translated & FRIDA_STRIP_MASK),
              "r" (FRIDA_FP_TO_SP (fp))
            : "x16", "x17"
        );

        *stored_pc_slot = GSIZE_TO_POINTER (resigned);
      }
      else
      {
        *stored_pc_slot = GSIZE_TO_POINTER (translated);
      }
#else
      *stored_pc_slot = GSIZE_TO_POINTER (translated);
#endif
    }
  }
}

static gpointer
frida_find_vtable (void)
{
  GumAddress result = 0;
  GumModule * libunwind;
  GumAddress export;
  uint64_t address;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  size_t size;
  const size_t max_size = 2048;

  libunwind = gum_process_find_module_by_name (FRIDA_LIBUNWIND_PATH);
  if (libunwind == NULL)
    goto beach;

  export = gum_module_find_export_by_name (libunwind, "unw_init_local");
  if (export == 0)
    export = gum_module_find_export_by_name (libunwind, "_Unwind_RaiseException");
  if (export == 0)
    goto beach;
  export = gum_strip_code_address (export);
  address = export;

#ifdef HAVE_ARM64
  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
#else
  cs_arch_register_x86 ();
  err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
#endif
  g_assert (err == CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = GSIZE_TO_POINTER (export);
  size = max_size;

#ifdef HAVE_ARM64
  {
    GumAddress last_adrp;
    guint last_adrp_reg;
    GumMemoryRange bss_range;

    bss_range.base_address = 0;
    gum_module_enumerate_sections (libunwind, (GumFoundSectionFunc) frida_find_bss_range, &bss_range);

    while (cs_disasm_iter (capstone, &code, &size, &address, insn))
    {
      if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
        break;
      if (insn->id == ARM64_INS_ADRP)
      {
        if (result != 0)
          break;
        last_adrp = (GumAddress) insn->detail->arm64.operands[1].imm;
        last_adrp_reg = insn->detail->arm64.operands[0].reg;
      }
      else if (insn->id == ARM64_INS_ADD && insn->detail->arm64.operands[0].reg == last_adrp_reg)
      {
        GumAddress candidate;
        gboolean is_bss;

        candidate = last_adrp + (GumAddress) insn->detail->arm64.operands[2].imm;

        is_bss = bss_range.base_address != 0 &&
            bss_range.base_address <= candidate &&
            candidate < bss_range.base_address + bss_range.size;
        if (!is_bss)
        {
          if (result == 0)
          {
            result = candidate;
            last_adrp = candidate;
          }
          else
          {
            result = candidate;
            break;
          }
        }
      }
      else if (result != 0)
      {
        break;
      }
    }
  }
#else
  while (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == X86_INS_RET)
      break;
    if (insn->id == X86_INS_LEA)
    {
      const cs_x86_op * op = &insn->detail->x86.operands[1];
      if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
      {
        result = address + op->mem.disp * op->mem.scale;
        break;
      }
    }
  }
#endif

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

beach:
  g_clear_object (&libunwind);

  return GSIZE_TO_POINTER (result);
}

#ifdef HAVE_ARM64

static gboolean
frida_find_bss_range (const GumSectionDetails * details, GumMemoryRange * range)
{
  if (strcmp (details->name, "__bss") == 0)
  {
    range->base_address = details->address;
    range->size = details->size;
    return FALSE;
  }

  return TRUE;
}

static gboolean
frida_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  gboolean result = FALSE;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  uint64_t address;
  size_t size = 4;

  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = gum_strip_code_pointer (*(gpointer *) vtable);
  address = GPOINTER_TO_SIZE (code);

  if (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
      *shift = 0;
    else
      *shift = -2 * GLIB_SIZEOF_VOID_P;

    result = TRUE;
  }

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

  return result;
}

#else

static gboolean
frida_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  GumAddress cursor = GPOINTER_TO_SIZE (vtable);
  GumAddress error = cursor + 16 * GLIB_SIZEOF_VOID_P;

  while (cursor < error && *(gpointer *) GSIZE_TO_POINTER (cursor) == NULL)
    cursor += GLIB_SIZEOF_VOID_P;
  if (cursor == error)
    return FALSE;

  if (frida_is_empty_function (GUM_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor))) &&
      frida_is_empty_function (GUM_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor + GLIB_SIZEOF_VOID_P))))
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable);
  }
  else
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable) - 2 * GLIB_SIZEOF_VOID_P;
  }

  return TRUE;
}

static gboolean
frida_is_empty_function (GumAddress address)
{
  gboolean matches = FALSE;
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = address;
  range.size = 6;

  /*
   * 55      push rbp
   * 4889e5  mov rbp, rsp
   * 5d      pop rbp
   * c3      ret
   */
  pattern = gum_match_pattern_new_from_string ("55 48 89 e5 5d c3");

  gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) frida_has_first_match, &matches);

  gum_match_pattern_unref (pattern);

  return matches;
}

static gboolean
frida_has_first_match (GumAddress address, gsize size, gboolean * matches)
{
  *matches = TRUE;
  return FALSE;
}

#endif

#endif
