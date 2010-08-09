namespace Zed.Service {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public void start () {
			foreach (var backend in backends)
				backend.start ();
		}

		public void add_backend (HostSessionBackend backend) {
			backends.add (backend);
			backend.provider_available.connect ((provider) => {
				provider_available (provider);
			});
			backend.provider_unavailable.connect ((provider) => {
				provider_unavailable (provider);
			});
		}
	}

	public interface HostSessionProvider : Object {
		public abstract async HostSession create () throws IOError;
	}

	[DBus (name = "org.boblycat.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws IOError;
	}

	public interface HostSessionBackend : Object {
		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public abstract void start ();
	}

	public struct HostProcessInfo {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public string? small_icon {
			get;
			private set;
		}

		public string? large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, string? small_icon, string? large_icon) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}
}
