namespace Zed {
	public class View.Chat : Object {
		public Gtk.Widget widget {
			get {
				return hbox;
			}
		}

		public Gtk.TreeView roster_view {
			get;
			private set;
		}

		public Gtk.TextView chat_view {
			get;
			private set;
		}

		private Gtk.HBox hbox;

		public Chat () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.CHAT_XML, -1);

				hbox = builder.get_object ("root_hbox") as Gtk.HBox;

				roster_view = builder.get_object ("roster_treeview") as Gtk.TreeView;
				chat_view = builder.get_object ("chat_textview") as Gtk.TextView;
			} catch (Error e) {
				error (e.message);
			}
		}
	}

	public class Presenter.Chat : Object {
		public View.Chat view {
			get;
			construct;
		}

		public Service.MucService muc_service {
			private get;
			construct;
		}

		private Gtk.ListStore roster_store;

		public Chat (View.Chat view, Service.MucService muc_service) {
			Object (view: view, muc_service: muc_service);

			roster_store = new Gtk.ListStore (1, typeof (string));
			view.roster_view.set_model (roster_store);
			view.roster_view.insert_column_with_attributes (-1, "JID", new Gtk.CellRendererText (), "text", 0);

			connect_signals ();
		}

		private void connect_signals () {
			muc_service.joined.connect ((who) => {
				Gtk.TreeIter iter;
				roster_store.append (out iter);
				roster_store.set (iter, 0, who);
			});
			muc_service.left.connect ((who) => {
				Gtk.TreeIter iter;
				if (!roster_store.get_iter_first (out iter))
					return;
				do {
					var val = Value (typeof (string));
					roster_store.get_value (iter, 0, out val);
					if (val.get_string () == who) {
						roster_store.remove (iter);
						return;
					}
				} while (roster_store.iter_next (ref iter));
			});

			muc_service.message.connect ((from, text) => {
				var buffer = view.chat_view.buffer;

				var builder = new StringBuilder ();
				if (buffer.get_char_count () > 0)
					builder.append ("\n");
				builder.append_printf ("<%s> %s", from, text);

				Gtk.TextIter iter;
				buffer.get_end_iter (out iter);
				buffer.insert (iter, builder.str, -1);
			});
		}
	}
}

