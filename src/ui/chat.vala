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

		public Service.XmppClient client {
			private get;
			construct;
		}

		private Gtk.ListStore roster_store;

		public Chat (View.Chat view, Service.XmppClient client) {
			Object (view: view, client: client);

			roster_store = new Gtk.ListStore (1, typeof (string));
			view.roster_view.set_model (roster_store);
			view.roster_view.insert_column_with_attributes (-1, "JID", new Gtk.CellRendererText (), "text", 0);

			Gtk.TreeIter iter;
			roster_store.append (out iter);
			roster_store.set (iter, 0, "zokum");
			roster_store.append (out iter);
			roster_store.set (iter, 0, "zole");

			view.chat_view.buffer.text = "<zokum> Endelig TG!\n<zole> Yay, TG FTW!\n<zokum> \\o/";
		}
	}
}

