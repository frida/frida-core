public class Zed.DarwinHostSession : Object, HostSession {
	private Fruitjector injector = new Fruitjector ();

	private const uint SERVER_LISTEN_PORT = 27042;
	private uint last_agent_port = SERVER_LISTEN_PORT + 1;

	public async Zed.HostProcessInfo[] enumerate_processes () throws IOError {
		return System.enumerate_processes ();
	}

	public async Zed.AgentSessionId attach_to (uint pid) throws IOError {
		var agent_path = Path.build_filename (Config.PKGLIBDIR, "zed-agent.dylib");
		var port = last_agent_port++;
		var listen_address = "tcp:host=127.0.0.1,port=%u".printf (port);
		injector.inject (pid, agent_path, listen_address);

		return Zed.AgentSessionId (port);
	}
}
