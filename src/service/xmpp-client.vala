using Wocky;

public class Zed.Service.XmppClient : Object {
	public Session? session {
		get;
		private set;
	}

	public Protocol.Jid? jid {
		get;
		private set;
	}

	public XmppClient () {
		Object ();

		notify["session"].connect (() => {
			if (session != null)
				register_handlers ();
		});
	}

	public async void close () {
		/* TODO: fix wocky
		try {
			var porter = session.porter;
			yield porter.close_async ();
		} catch (PorterError porter_error) {
		}
		*/
	}

	public async bool login (string jid, string password, string? host) {
		var connector = new Connector (jid, password, "Frida");

		if (host != null) {
			connector.xmpp_server = host;
			connector.xmpp_port = 5222;
			connector.tls_required = false;
			connector.plaintext_auth_allowed = true;
		}

		try {
			string attributed_jid, sid;
			var connection = yield connector.connect_async (out attributed_jid, out sid);

			this.jid = new Protocol.Jid.from_string (attributed_jid);

			session = new Session (connection);
			session.porter.closing.connect (reset);
			session.porter.remote_closed.connect (reset);
			session.porter.remote_error.connect (reset);

			session.start ();

			return true;
		} catch (Error e) {
			reset ();
		}

		return false;
	}

	private void reset () {
		session = null;
		jid = null;
	}

	private void register_handlers () {
		var porter = session.porter;

		porter.register_handler (StanzaType.IQ, StanzaSubType.GET, null, 0, default_iq_handler);
		porter.register_handler (StanzaType.IQ, StanzaSubType.SET, null, 0, default_iq_handler);
	}

	private bool default_iq_handler (Porter porter, XmppStanza stanza) {
		var reply = stanza.build_iq_error (
			BuildTag.NODE, "error", BuildTag.NODE_ATTRIBUTE, "type", "cancel",
				BuildTag.NODE, "feature-not-implemented",
					BuildTag.NODE_XMLNS, Namespaces.Xmpp.STANZAS,
				BuildTag.NODE_END,
			BuildTag.NODE_END);
		porter.send (reply);

		return true;
	}
}
