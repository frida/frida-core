public class Zed.Protocol.Jid {
	public string? node;
	public string domain;
	public string? resource;

	public string bare {
		get {
			if (_bare == null) {
				if (node != null)
					_bare = node + "@" + domain;
				else
					_bare = domain;
			}

			return _bare;
		}
	}
	private string? _bare;

	public string full {
		get {
			if (_full == null) {
				if (resource != null)
					_full = bare + "/" + resource;
				else
					_full = bare;
			}

			return _full;
		}
	}
	private string? _full;

	public Jid (string? node, string domain, string? resource) {
		this.node = node;
		this.domain = domain;
		this.resource = resource;
	}

	public Jid.from_string (string jid) {
		Wocky.Utils.decode_jid (jid, out node, out domain, out resource);
		_full = jid;
	}
}

