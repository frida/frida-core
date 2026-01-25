#ifndef __FRIDA_ATOMICS_H__
#define __FRIDA_ATOMICS_H__

#ifdef _MSC_VER

/* TODO: Add once needed. */

#else

static inline guint64 frida_atomics_load_u64_acquire (volatile guint64 * p)
{
  return __atomic_load_n (p, __ATOMIC_ACQUIRE);
}

static inline void frida_atomics_store_u64_release (volatile guint64 * p, guint64 v)
{
  __atomic_store_n (p, v, __ATOMIC_RELEASE);
}

static inline guint32 frida_atomics_load_u32_acquire (volatile guint32 * p)
{
  return __atomic_load_n (p, __ATOMIC_ACQUIRE);
}

#endif

#endif
