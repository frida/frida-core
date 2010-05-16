public abstract class Zed.Service.BaseService : Object {
	public XmppClient client {
		protected get;
		construct;
	}

	construct {
		client.notify["session"].connect (() => {
			if (client.session != null)
				register_handlers ();
		});
	}

	protected virtual void register_handlers () {
	}
}
