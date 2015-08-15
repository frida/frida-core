#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"
#include "xattr.h"

int fsetfilecon(int fd, const char *context)
{
	return fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1,
			 0);
}

