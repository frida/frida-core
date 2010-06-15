public class Zed.ProcessInfo : Object {
	public uint pid {
		get;
		private set;
	}

	public string name {
		get;
		private set;
	}

	public Gdk.Pixbuf? small_icon {
		get;
		private set;
	}

	public Gdk.Pixbuf? large_icon {
		get;
		private set;
	}

	public ProcessInfo (uint pid, string name, Gdk.Pixbuf? small_icon = null, Gdk.Pixbuf? large_icon = null) {
		this.pid = pid;
		this.name = name;
		this.small_icon = small_icon;
		this.large_icon = large_icon;
	}
}

