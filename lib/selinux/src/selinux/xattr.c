#include "xattr.h"

#ifndef HAVE_SYS_XATTR_H

#include <sys/syscall.h>

ssize_t selinux_getxattr(const char *path, const char *name, void *value, size_t size)
{
	return syscall(__NR_getxattr, path, name, value, size);
}

ssize_t selinux_lgetxattr(const char *path, const char *name, void *value, size_t size)
{
	return syscall(__NR_lgetxattr, path, name, value, size);
}

ssize_t selinux_fgetxattr(int fd, const char *name, void *value, size_t size)
{
	return syscall(__NR_fgetxattr, fd, name, value, size);
}

int selinux_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	return syscall(__NR_setxattr, path, name, value, size, flags);
}

int selinux_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	return syscall(__NR_lsetxattr, path, name, value, size, flags);
}

int selinux_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
	return syscall(__NR_fsetxattr, fd, name, value, size, flags);
}

#endif

