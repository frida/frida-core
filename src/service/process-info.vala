namespace Zed {
	public class ProcessInfo : Object {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public Gdk.Pixbuf? icon {
			get;
			private set;
		}

		public ProcessInfo (uint pid, string name, Gdk.Pixbuf? icon = null) {
			this.pid = pid;
			this.name = name;
			this.icon = icon;
		}
	}
}

