namespace Frida {
	public interface PolicySoftener : Object {
		public abstract void soften (uint pid) throws Error;
	}

	public class NullPolicySoftener : Object, PolicySoftener {
		public void soften (uint pid) throws Error {
		}
	}

#if IOS
	public class ElectraPolicySoftener : Object, PolicySoftener {
		private const string LIBJAILBREAK_PATH = "/usr/lib/libjailbreak.dylib";

		private Module libjailbreak;
		private ConnectFunc jb_connect;
		private DisconnectFunc jb_disconnect;
		private EntitleNowFunc jb_entitle_now;

		private DaemonConnection connection;

		construct {
			libjailbreak = Module.open (LIBJAILBREAK_PATH, BIND_LAZY);
			assert (libjailbreak != null);

			jb_connect = (ConnectFunc) resolve_symbol ("jb_connect");
			jb_disconnect = (DisconnectFunc) resolve_symbol ("jb_disconnect");
			jb_entitle_now = (EntitleNowFunc) resolve_symbol ("jb_entitle_now");

			connection = jb_connect ();

			entitle_and_platformize (Posix.getpid ());
		}

		~ElectraPolicySoftener () {
			jb_disconnect (connection);
		}

		public static bool is_available () {
			return FileUtils.test (LIBJAILBREAK_PATH, FileTest.EXISTS);
		}

		public void soften (uint pid) throws Error {
			entitle_and_platformize (pid);
		}

		private void entitle_and_platformize (uint pid) {
			jb_entitle_now (connection, (Posix.pid_t) pid);
		}

		private void * resolve_symbol (string name) {
			void * symbol;
			bool found = libjailbreak.symbol (name, out symbol);
			assert (found);
			return symbol;
		}

		[CCode (has_target = false)]
		private delegate DaemonConnection ConnectFunc ();
		[CCode (has_target = false)]
		private delegate void DisconnectFunc (DaemonConnection connection);
		[CCode (has_target = false)]
		private delegate Gum.Darwin.Status EntitleNowFunc (DaemonConnection connection, Posix.pid_t pid);

		[Compact]
		[CCode (free_function = "")]
		private class DaemonConnection {
		}
	}
#endif
}
