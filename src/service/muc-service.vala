public class Zed.Service.MucService : BaseService {
	private Wocky.Muc muc;
	private Gee.Set<string> members;

	public signal void message (string from, string text);
	public signal void joined (string who);
	public signal void left (string who);

	private static const string DEFAULT_CONFERENCE_SERVER = "conference.jabber.org";

	public MucService (XmppClient client) {
		Object (client: client);

		connect_signals ();
	}

	private void connect_signals () {
		client.notify["session"].connect (() => {
			if (client.session != null)
				join_muc ();
			else
				cleanup_muc ();
		});
	}

	private void join_muc () {
		var conference_server = Environment.get_variable ("FRIDA_CONFERENCE_SERVER");
		if (conference_server == null)
			conference_server = DEFAULT_CONFERENCE_SERVER;

		var room_jid = new Protocol.Jid ("frida", conference_server, client.jid.node);

		members = new Gee.HashSet<string> ();

		muc = Object.new (typeof (Wocky.Muc),
			"porter", client.session.porter,
			"jid", room_jid.full,
			"user", client.jid.full) as Wocky.Muc;

		muc.presence.connect ((stanza, code, who) => {
			if (members.add (who.nick))
				joined (who.nick);
		});
		muc.left.connect ((stanza, code, who, actor_jid, why, msg) => {
			if (members.remove (who.nick)) {
				left (who.nick);
			}
		});

		muc.message.connect ((stanza, type, xmpp_id, stamp, who, text, subject, state) => {
			if (who == null)
				return;
			if (type != Wocky.MucMsgType.NORMAL && type != Wocky.MucMsgType.ACTION)
				return;
			message (who.nick, text);
		});
		muc.join ();
	}

	private void cleanup_muc () {
		members = null;
		muc = null;
	}
}
