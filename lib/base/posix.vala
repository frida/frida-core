namespace Frida {
	public sealed class StdioPipes : Object {
		public OutputStream? input {
			get;
			construct;
		}

		public InputStream output {
			get;
			construct;
		}

		public InputStream error {
			get;
			construct;
		}

		public StdioPipes (FileDescriptor? input, FileDescriptor output, FileDescriptor error) {
			Object (
				input: (input != null) ? new UnixOutputStream (ensure_nonblocking (input.steal ()), true) : null,
				output: new UnixInputStream (ensure_nonblocking (output.steal ()), true),
				error: new UnixInputStream (ensure_nonblocking (error.steal ()), true)
			);
		}

		private static int ensure_nonblocking (int fd) {
			try {
				Unix.set_fd_nonblocking (fd, true);
				return fd;
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	public class FileDescriptor : Object, FileDescriptorBased {
		public int handle;

		public FileDescriptor (int handle) {
			this.handle = handle;
		}

		~FileDescriptor () {
			if (handle != -1)
				Posix.close (handle);
		}

		public int steal () {
			int result = handle;
			handle = -1;
			return result;
		}

		public int get_fd () {
			return handle;
		}

		public size_t pread (uint8[] buf, uint64 offset) throws Error {
			while (true) {
				ssize_t res = Posix.pread (handle, buf, buf.length, (Posix.off_t) offset);
				if (res == -1) {
					if (errno == Posix.EINTR)
						continue;
					throw new Error.TRANSPORT ("%s", strerror (errno));
				}

				return res;
			}
		}

		public void pread_all (uint8[] buf, uint64 offset) throws Error {
			size_t total = 0;

			while (total != buf.length) {
				void * dst = (uint8 *) buf + total;
				size_t remaining = buf.length - total;

				while (true) {
					ssize_t res = Posix.pread (handle, dst, remaining, (Posix.off_t) (offset + total));
					if (res == -1) {
						if (errno == Posix.EINTR)
							continue;
						throw new Error.TRANSPORT ("%s", strerror (errno));
					}

					if (res == 0)
						throw new Error.TRANSPORT ("Unexpected EOF: read %zu of %zu bytes", total, buf.length);

					total += (size_t) res;
					break;
				}
			}
		}

		public size_t pwrite (uint8[] buf, uint64 offset) throws Error {
			while (true) {
				ssize_t res = Posix.pwrite (handle, buf, buf.length, (Posix.off_t) offset);
				if (res == -1) {
					if (errno == Posix.EINTR)
						continue;
					throw new Error.TRANSPORT ("%s", strerror (errno));
				}

				return res;
			}
		}

		public void pwrite_all (uint8[] buf, uint64 offset) throws Error {
			size_t total = 0;

			while (total != buf.length) {
				uint8[] chunk = buf[total : buf.length];

				while (true) {
					ssize_t res = Posix.pwrite (handle, chunk, chunk.length, (Posix.off_t) (offset + total));
					if (res == -1) {
						if (errno == Posix.EINTR)
							continue;
						throw new Error.TRANSPORT ("%s", strerror (errno));
					}

					total += (size_t) res;
					break;
				}
			}
		}
	}

	public StdioPipes? make_stdio_pipes (Stdio stdio, bool in_supported, out FileDescriptor? in_fd, out string? in_name,
			out FileDescriptor? out_fd, out string? out_name, out FileDescriptor? err_fd, out string? err_name) throws Error {
		if (stdio == PIPE) {
			FileDescriptor? in_write = null;
			FileDescriptor? out_read, err_read;

			if (in_supported) {
				make_stdio_pipe (out in_fd, out in_write, out in_name);
			} else {
				in_fd = null;
				in_name = null;
			}
			make_stdio_pipe (out out_read, out out_fd, out out_name);
			make_stdio_pipe (out err_read, out err_fd, out err_name);

			return new StdioPipes (in_write, out_read, err_read);
		} else {
			in_fd = null;
			in_name = null;

			out_fd = null;
			out_name = null;

			err_fd = null;
			err_name = null;

			return null;
		}
	}

	public void make_stdio_pipe (out FileDescriptor read, out FileDescriptor write, out string? name = null) throws Error {
#if HAVE_OPENPTY
		int rfd = -1, wfd = -1;
		char buf[Posix.Limits.PATH_MAX];
		var res =
#if DARWIN
			Darwin.XNU.openpty (out rfd, out wfd, buf, null, null)
#elif LINUX
			Linux.openpty (out rfd, out wfd, buf, null, null)
#elif FREEBSD
			FreeBSD.openpty (out rfd, out wfd, buf, null, null)
#endif
			;
		if (res == -1)
			throw new Error.NOT_SUPPORTED ("Unable to open PTY: %s", strerror (errno));
		name = (string) buf;

		enable_close_on_exec (rfd);
		enable_close_on_exec (wfd);

		disable_sigpipe (rfd);
		disable_sigpipe (wfd);

		configure_terminal_attributes (rfd);

		read = new FileDescriptor (rfd);
		write = new FileDescriptor (wfd);
#else
		name = null;

		try {
			int fds[2];
			Unix.open_pipe (fds, Posix.FD_CLOEXEC);

			read = new FileDescriptor (fds[0]);
			write = new FileDescriptor (fds[1]);
		} catch (GLib.Error e) {
			throw new Error.NOT_SUPPORTED ("Unable to open pipe: %s", e.message);
		}
#endif
	}

#if HAVE_OPENPTY
	private void enable_close_on_exec (int fd) {
		Posix.fcntl (fd, Posix.F_SETFD, Posix.fcntl (fd, Posix.F_GETFD) | Posix.FD_CLOEXEC);
	}

	private void disable_sigpipe (int fd) {
#if DARWIN
		Posix.fcntl (fd, Darwin.XNU.F_SETNOSIGPIPE, true);
#endif
	}

	private void configure_terminal_attributes (int fd) {
		var tios = Posix.termios ();
		Posix.tcgetattr (fd, out tios);

		tios.c_oflag &= ~Posix.ONLCR;
		tios.c_cflag = (tios.c_cflag & Posix.CLOCAL) | Posix.CS8 | Posix.CREAD | Posix.HUPCL;
		tios.c_lflag &= ~Posix.ECHO;

		Posix.tcsetattr (fd, 0, tios);
	}
#endif

	namespace ChildProcess {
		public async WaitResult wait_for_next_stop (uint pid, Cancellable? cancellable) throws Error, IOError {
			var main_context = MainContext.get_thread_default ();

			bool timed_out = false;
			var timeout_source = new TimeoutSource.seconds (5);
			timeout_source.set_callback (() => {
				timed_out = true;
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			int status = 0;
			uint[] delays = { 0, 1, 2, 5, 10, 20, 50, 250 };

			try {
				for (uint i = 0; !timed_out && !cancellable.set_error_if_cancelled (); i++) {
					int res = Posix.waitpid ((Posix.pid_t) pid, out status, Posix.WNOHANG);
					if (res == -1)
						throw new Error.NOT_SUPPORTED ("Unable to wait for next stop: %s", strerror (errno));
					if (res != 0)
						break;

					uint delay_ms = (i < delays.length) ? delays[i] : delays[delays.length - 1];

					var delay_source = new TimeoutSource (delay_ms);
					delay_source.set_callback (wait_for_next_stop.callback);
					delay_source.attach (main_context);

					var cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (wait_for_next_stop.callback);
					cancel_source.attach (main_context);

					yield;

					cancel_source.destroy ();
					delay_source.destroy ();
				}
			} finally {
				timeout_source.destroy ();
			}

			if (timed_out)
				throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for stop from process with PID %u", pid);

			return WaitResult (pid, status);
		}
	}

	public struct WaitResult {
		public uint pid;
		public int status;

		public WaitKind kind;

		public uint exit_status;

		public Posix.Signal term_signal;

		public Posix.Signal stop_signal;

		public WaitResult (uint pid, int status) {
			this.pid = pid;
			this.status = status;

			kind = WaitKind.OTHER;
			exit_status = 0;
			term_signal = 0;
			stop_signal = 0;

			if (PosixStatus.is_exit (status)) {
				kind = WaitKind.EXITED;
				exit_status = PosixStatus.parse_exit_status (status);
			} else if (PosixStatus.is_signaled (status)) {
				kind = WaitKind.SIGNALED;
				term_signal = PosixStatus.parse_termination_signal (status);
			} else if (PosixStatus.is_stopped (status)) {
				kind = WaitKind.STOPPED;

				stop_signal = PosixStatus.parse_stop_signal (status);
			}
		}

		public void check_stopped () throws Error {
			switch (kind) {
				case WaitKind.EXITED:
					throw new Error.NOT_SUPPORTED ("Target exited with status %u", exit_status);
				case WaitKind.SIGNALED:
					throw new Error.NOT_SUPPORTED ("Target terminated with signal %u", term_signal);
				case WaitKind.STOPPED:
					return;
				default:
					throw new Error.NOT_SUPPORTED ("Unexpected status: 0x%08x", status);
			}
		}
	}

	public enum WaitKind {
		EXITED,
		SIGNALED,
		STOPPED,
		OTHER
	}

	namespace PosixStatus {
		[CCode (cname = "WIFEXITED", cheader_filename = "sys/wait.h")]
		private extern bool is_exit (int status);

		[CCode (cname = "WIFSIGNALED", cheader_filename = "sys/wait.h")]
		private extern bool is_signaled (int status);

		[CCode (cname = "WIFSTOPPED", cheader_filename = "sys/wait.h")]
		private extern bool is_stopped (int status);

		[CCode (cname = "WEXITSTATUS", cheader_filename = "sys/wait.h")]
		private extern uint parse_exit_status (int status);

		[CCode (cname = "WTERMSIG", cheader_filename = "sys/wait.h")]
		private extern Posix.Signal parse_termination_signal (int status);

		[CCode (cname = "WSTOPSIG", cheader_filename = "sys/wait.h")]
		private extern Posix.Signal parse_stop_signal (int status);
	}
}
