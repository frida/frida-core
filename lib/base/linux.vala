namespace Frida {
	private uint linux_major = 0;
	private uint linux_minor = 0;

	public bool check_kernel_version (uint major, uint minor) {
		if (linux_major == 0) {
			var name = Posix.utsname ();
			name.release.scanf ("%u.%u", out linux_major, out linux_minor);
		}

		return (linux_major == major && linux_minor >= minor) || linux_major > major;
	}

	public sealed class PidFileDescriptor : FileDescriptor {
		private uint pid;

		private PidFileDescriptor (int fd, uint pid) {
			base (fd);
			this.pid = pid;
		}

		public static bool is_supported () {
			return check_kernel_version (5, 3);
		}

		public static bool getfd_is_supported () {
			return check_kernel_version (5, 6);
		}

		public static PidFileDescriptor from_pid (uint pid) throws Error {
			int fd = pidfd_open (pid, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new PidFileDescriptor (fd, pid);
		}

		public FileDescriptor getfd (int targetfd) throws Error {
			int fd = pidfd_getfd (handle, targetfd, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new FileDescriptor (fd);
		}

		private static int pidfd_open (uint pid, uint flags) {
			return Linux.syscall (SysCall.pidfd_open, pid, flags);
		}

		private static int pidfd_getfd (int pidfd, int targetfd, uint flags) {
			return Linux.syscall (SysCall.pidfd_getfd, pidfd, targetfd, flags);
		}

		[NoReturn]
		private static void throw_pidfd_error (uint pid, int err) throws Error {
			switch (err) {
				case Posix.ESRCH:
					throw new Error.PROCESS_NOT_FOUND ("Process not found");
				case Posix.EPERM:
					throw new Error.PERMISSION_DENIED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
				default:
					throw new Error.NOT_SUPPORTED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
			}
		}
	}

	namespace MemoryFileDescriptor {
		public bool is_supported () {
			return check_kernel_version (3, 17);
		}

		public static FileDescriptor from_bytes (string name, Bytes bytes) {
			assert (is_supported ());

			var fd = new FileDescriptor (memfd_create (name, 0));
			unowned uint8[] data = bytes.get_data ();
			ssize_t n = Posix.write (fd.handle, data, data.length);
			assert (n == data.length);
			return fd;
		}

		private int memfd_create (string name, uint flags) {
			return Linux.syscall (SysCall.memfd_create, name, flags);
		}
	}
}
