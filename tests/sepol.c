#include "frida-selinux.h"

int
main (int argc, char * argv[])
{
  frida_selinux_patch_policy ();
  return 0;
}

