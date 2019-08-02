namespace Frida {
#if WINDOWS
	public class FileDescriptorTablePadder {
		public static FileDescriptorTablePadder obtain () {
			return new FileDescriptorTablePadder ();
		}

		public void move_descriptor_if_needed (ref int fd) {
		}
	}
#else
	public class FileDescriptorTablePadder {
		private const int MIN_TABLE_SIZE = 32;

		private static unowned FileDescriptorTablePadder shared_instance = null;
		private int[] fds = new int[0];

		public static FileDescriptorTablePadder obtain () {
			FileDescriptorTablePadder padder;

			if (shared_instance == null) {
				padder = new FileDescriptorTablePadder ();
				shared_instance = padder;
			} else {
				padder = shared_instance;
				padder.open_needed_descriptors ();
			}

			return padder;
		}

		private FileDescriptorTablePadder () {
			open_needed_descriptors ();
		}

		~FileDescriptorTablePadder () {
			foreach (int fd in fds) {
				close_descriptor (fd);

				Gum.Cloak.remove_file_descriptor (fd);
			}

			shared_instance = null;
		}

		public void move_descriptor_if_needed (ref int fd) {
			if (fd >= MIN_TABLE_SIZE)
				return;

			int pair[2];
			if (Posix.pipe (pair) == -1)
				return;

			if (Posix.dup2 (fd, pair[0]) != -1) {
				fds += fd;
				Gum.Cloak.add_file_descriptor (fd);
				fd = pair[0];
			} else {
				close_descriptor (pair[0]);
			}

			close_descriptor (pair[1]);
		}

		private void open_needed_descriptors () {
			int old_size = fds.length;

			do {
				if (!grow_table ())
					break;
			} while (fds[fds.length - 1] < MIN_TABLE_SIZE - 1);

			int n = fds.length;
			int fd = -1;
			for (int i = n - 1; i >= 0 && (fd = fds[i]) >= MIN_TABLE_SIZE; i--) {
				close_descriptor (fd);
				n--;
			}
			fds.resize (n);

			foreach (int new_fd in fds[old_size:fds.length])
				Gum.Cloak.add_file_descriptor (new_fd);
		}

		private bool grow_table () {
			int pair[2];
			if (Posix.pipe (pair) == -1)
				return false;
			fds += pair[0];
			fds += pair[1];
			return true;
		}

		private static void close_descriptor (int fd) {
			int res = -1;
			do {
				res = Posix.close (fd);
			} while (res == -1 && Posix.errno == Posix.EINTR);
		}
	}
#endif
}
