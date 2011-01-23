public abstract class Zed.BaseService : Object {
	public XmppClient client {
		protected get;
		construct;
	}

	construct {
		client.notify["is-logged-in"].connect (() => {
			if (client.is_logged_in)
				register_handlers ();
		});
	}

	protected virtual void register_handlers () {
	}
}
