#include "zed-core.h"

#include <udis86.h>

char *
zed_presenter_agent_session_disassemble (ZedPresenterAgentSession * self,
    guint8 * bytes, int bytes_length1, guint * instruction_length)
{
  ud_t ud_obj;

  ud_init (&ud_obj);
  ud_set_mode (&ud_obj, 32);
  ud_set_syntax (&ud_obj, UD_SYN_INTEL);
  ud_set_input_buffer (&ud_obj, bytes, bytes_length1);

  *instruction_length = ud_disassemble (&ud_obj);

  return g_strdup (ud_insn_asm (&ud_obj));
}
