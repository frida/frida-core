[CCode (prefix = "", lower_case_cprefix = "", cheader_filename = "config.h")]
namespace Config {
	public const string PACKAGE_NAME;
	public const string PACKAGE_STRING;
	public const string PACKAGE_VERSION;

	public const string PKGDATADIR;
	public const string PKGLIBDIR;
	public const string PKGTESTDIR;
}

[CCode (cprefix = "G", lower_case_cprefix = "g_", cheader_filename = "glib.h", gir_namespace = "GLib", gir_version = "2.0")]
namespace Zed.TextUtil {
	unichar * utf8_to_utf16 (string str, long len = -1, out long items_read = null, out long items_written = null) throws GLib.Error;
}
