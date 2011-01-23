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

		public Gtk.Entry chat_entry {
			get;
			private set;
		}

		public bool can_chat {
			get {
				return (chat_entry.get_flags () & Gtk.WidgetFlags.SENSITIVE) != 0;
			}

			set {
				chat_entry.sensitive = value;
			}
		}

		private Gtk.HBox hbox;

		public Chat () {
			try {
				var builder = new Gtk.Builder ();
				var blob = Zed.Data.Ui.get_chat_ui_blob ();
				builder.add_from_string ((string) blob.data, blob.size);

				hbox = builder.get_object ("root_hbox") as Gtk.HBox;

				roster_view = builder.get_object ("roster_treeview") as Gtk.TreeView;
				chat_view = builder.get_object ("chat_textview") as Gtk.TextView;
				chat_entry = builder.get_object ("chat_entry") as Gtk.Entry;
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

		public MucService muc_service {
			private get;
			construct;
		}

		private Gtk.ListStore roster_store;
		private Gtk.TextMark chat_scroll_mark;

		public Chat (View.Chat view, MucService muc_service) {
			Object (view: view, muc_service: muc_service);

			roster_store = new Gtk.ListStore (1, typeof (string));
			roster_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);
			view.roster_view.set_model (roster_store);
			view.roster_view.insert_column_with_attributes (-1, "JID", new Gtk.CellRendererText (), "text", 0);

			chat_scroll_mark = new Gtk.TextMark ("scrollmark", false);
			var buffer = view.chat_view.buffer;
			Gtk.TextIter iter;
			buffer.get_end_iter (out iter);
			buffer.add_mark (chat_scroll_mark, iter);

			connect_signals ();

			view.can_chat = false;
		}

		private void connect_signals () {
			muc_service.you_joined.connect (() => {
				view.can_chat = true;

				roster_store.clear ();
				foreach (string nick in muc_service.members ()) {
					Gtk.TreeIter iter;
					roster_store.append (out iter);
					roster_store.set (iter, 0, nick);
				}
			});
			muc_service.you_parted.connect (() => {
				view.can_chat = false;

				roster_store.clear ();
			});
			muc_service.user_presence_received.connect ((who) => {
				Gtk.TreeIter iter;
				if (!find_roster_store_row_for_user (who, out iter)) {
					roster_store.append (out iter);
					roster_store.set (iter, 0, who);
				}
			});
			muc_service.user_parted.connect ((who) => {
				Gtk.TreeIter iter;
				if (find_roster_store_row_for_user (who, out iter))
					roster_store.remove (iter);
			});

			muc_service.message.connect ((from, text) => {
				var buffer = view.chat_view.buffer;

				Gtk.TextIter iter;
				buffer.get_end_iter (out iter);

				if (buffer.get_char_count () > 0)
					buffer.insert (iter, "\n", -1);

				view.chat_view.scroll_to_mark (chat_scroll_mark, 0.0, true, 0.0, 1.0);

				buffer.insert (iter, "<%s> %s".printf (from, text), -1);
			});

			view.chat_entry.activate.connect (() => {
				if (view.chat_entry.text != "") {
					muc_service.send (view.chat_entry.text);
					view.chat_entry.text = "";
				}
			});
		}

		private bool find_roster_store_row_for_user (string who, out Gtk.TreeIter iter) {
			if (!roster_store.get_iter_first (out iter))
				return false;

			do {
				var val = Value (typeof (string));
				roster_store.get_value (iter, 0, out val);
				if (val.get_string () == who)
					return true;
			} while (roster_store.iter_next (ref iter));

			return false;
		}
	}
}

