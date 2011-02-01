namespace Zed.System {
	public static extern Zed.HostProcessInfo[] enumerate_processes ();
	public static extern void kill (uint pid);
}

