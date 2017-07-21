#ifndef _SELINUX_XATTR_H_
#define _SELINUX_XATTR_H_

#ifdef HAVE_SYS_XATTR_H
# include <sys/xattr.h>
#else
# include <stdint.h>
# include <unistd.h>

ssize_t selinux_getxattr(const char *path, const char *name, void *value, size_t size);
ssize_t selinux_lgetxattr(const char *path, const char *name, void *value, size_t size);
ssize_t selinux_fgetxattr(int fd, const char *name, void *value, size_t size);
int selinux_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int selinux_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int selinux_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);

# define getxattr selinux_getxattr
# define lgetxattr selinux_lgetxattr
# define fgetxattr selinux_fgetxattr
# define setxattr selinux_setxattr
# define lsetxattr selinux_lsetxattr
# define fsetxattr selinux_fsetxattr
#endif

#endif
