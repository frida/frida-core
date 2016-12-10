namespace Frida.Test {
	public class Process : Object {
		public void * handle {
			get;
			construct;
		}

		public uint id {
			get;
			construct;
		}

		public unowned string filename {
			get {
				if (_filename == null) {
					_filename = ProcessBackend.filename_of (handle).replace ("/./", "/");
				}

				return _filename;
			}
		}
		private string _filename = null;

		public static Process current {
			owned get {
				return new Process (ProcessBackend.self_handle (), ProcessBackend.self_id ());
			}
		}

		private Process (void * handle, uint id) {
			Object (handle: handle, id: id);
		}

		public static Process start (string path, string[]? args = null, string[]? env = null, Arch arch = Arch.CURRENT) throws Error {
			var argv = new string[1 + ((args != null) ? args.length : 0)];
			argv[0] = path;
			if (args != null) {
				for (var i = 0; i != args.length; i++)
					argv[1 + i] = args[i];
			}

			string[] envp = (env != null) ? env : Environ.get ();

			void * handle;
			uint id;
			ProcessBackend.do_start (path, argv, envp, arch, out handle, out id);

			return new Process (handle, id);
		}

		public int join (uint timeout_msec = 0) throws Error {
			return ProcessBackend.do_join (handle, timeout_msec);
		}

		public ResourceUsageSnapshot snapshot_resource_usage () {
			return ProcessBackend.snapshot_resource_usage (handle);
		}
	}

	public class ResourceUsageSnapshot : Object {
		protected HashTable<string, uint> metrics = new HashTable<string, uint> (str_hash, str_equal);

		public void assert_equals (ResourceUsageSnapshot previous_snapshot) {
			uint num_differences = 0;

			var previous_metrics = previous_snapshot.metrics;

			metrics.for_each ((key, current_value) => {
				var previous_value = previous_metrics[key];
				if (current_value != previous_value) {
					if (num_differences == 0) {
						printerr (
							"\n\n" +
							"***************************\n" +
							"UH-OH, RESOURCE LEAK FOUND!\n" +
							"***************************\n" +
							"\n" +
							"TYPE\tBEFORE\tAFTER\n"
						);
					}

					printerr ("%s\t%u\t%u\n", key, previous_value, current_value);

					num_differences++;
				}
			});

			if (num_differences > 0)
				printerr ("\n");

			assert (num_differences == 0);
		}
	}

	namespace ProcessBackend {
		private extern void * self_handle ();
		private extern uint self_id ();
		private extern string filename_of (void * handle);
		private extern void do_start (string path, string[] argv, string[] envp, Arch arch, out void * handle, out uint id) throws Error;
		private extern int do_join (void * handle, uint timeout_msec) throws Error;
		private extern ResourceUsageSnapshot snapshot_resource_usage (void * handle);
	}
}
