[CCode (cprefix = "MxGtk", lower_case_cprefix = "mx_gtk_", gir_namespace = "MxGtk", gir_version = "1.0")]
namespace MxGtk {
	[CCode (cheader_filename = "mx-gtk/mx-gtk.h")]
	public class Frame : Gtk.Frame, Gtk.Buildable {
		[CCode (type = "GtkWidget*", has_construct_function = false)]
		public Frame ();
	}
}
