namespace Zed {
	public class View.ProcessInfoLabel : Gtk.VBox {
		public Gtk.Image icon {
			get;
			private set;
		}

		public Gtk.Label label {
			get;
			private set;
		}

		public ProcessInfoLabel () {
			icon = new Gtk.Image ();
			pack_start (icon, false, false, 5);

			label = new Gtk.Label (null);
			pack_start (label, false, false, 0);

			show_all ();
		}
	}

	public class Presenter.ProcessInfoLabel : Object {
		public View.ProcessInfoLabel view {
			get;
			construct;
		}

		public ProcessInfo process_info {
			get;
			construct;
		}

		public ProcessInfoLabel (View.ProcessInfoLabel view, ProcessInfo process_info) {
			Object (view: view, process_info: process_info);

			var icon = process_info.icon;
			if (icon != null)
				view.icon.set_from_pixbuf (icon);
			else
				view.icon.hide ();

			view.label.set_markup ("<b>%s</b> (%u)".printf (process_info.name, process_info.pid));
		}
	}
}
