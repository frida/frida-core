using Wocky;

public class Zed.Service.MucService : BaseService {
	private Muc muc;

	public signal void you_joined ();
	public signal void you_parted ();
	public signal void user_presence_received (string who);
	public signal void user_parted (string who);
	public signal void message (string from, string text);

	private static const string DEFAULT_CONFERENCE_SERVER = "conference.jabber.org";

	public MucService (XmppClient client) {
		Object (client: client);

		connect_signals ();
	}

	public Gee.List<string> members () {
		var result = new Gee.ArrayList<string> ();

		result.add (muc.nickname);

		List<weak string> member_jids = (List<weak string>) muc.members ().get_keys ();
		foreach (string raw_jid in member_jids) {
			var jid = new Protocol.Jid.from_string (raw_jid);
			result.add (jid.resource);
		}

		return result;
	}

	public void send (string message) {
		var room_jid = new Protocol.Jid.from_string (muc.jid);
		var stanza = XmppStanza.build (StanzaType.MESSAGE, StanzaSubType.GROUPCHAT, client.jid.full, room_jid.bare,
			BuildTag.NODE, "body",
				BuildTag.NODE_TEXT, message,
			BuildTag.NODE_END);
		client.session.porter.send (stanza);
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

		muc = Object.new (typeof (Muc),
			"porter", client.session.porter,
			"jid", room_jid.full,
			"user", client.jid.full) as Muc;

		muc.joined.connect ((stanza, code) => {
			you_joined ();
		});
		muc.parted.connect ((stanza, code, actor_jid, why, msg) => {
			you_parted ();
		});
		muc.presence.connect ((stanza, code, who) => {
			user_presence_received (who.nick);
		});
		muc.left.connect ((stanza, code, who, actor_jid, why, msg) => {
			user_parted (who.nick);
		});

		muc.message.connect ((stanza, type, xmpp_id, stamp, who, text, subject, state) => {
			if (who == null)
				return;
			if (type != MucMsgType.NORMAL && type != MucMsgType.ACTION)
				return;
			message (who.nick, text);
		});
		muc.join ();
	}

	private void cleanup_muc () {
		muc = null;
	}
}
