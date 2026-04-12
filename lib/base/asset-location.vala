namespace Frida {
	public class AssetLocation : Object {
		public string libdir {
			get;
			construct;
		}

		public static AssetLocation? detect () {
			var module_path = detect_module_path ();
			if (module_path == null)
				return null;

			var lib_dir = Path.get_dirname (module_path);

			return new AssetLocation (lib_dir);
		}

		private AssetLocation (string libdir) {
			Object (libdir: libdir);
		}

		public string derive_asset_dir (string libdir_name, string arch) {
			return Path.build_filename (libdir, libdir_name, arch);
		}

		public string derive_asset_path (string libdir_name, string arch, string filename) {
			return Path.build_filename (libdir, libdir_name, arch, filename);
		}

		public string derive_plugin_path (string libdir_name, string filename) {
			return Path.build_filename (libdir, libdir_name, "plugins", filename);
		}

		private static string? detect_module_path () {
			string? path = null;
			Gum.Address our_address = Gum.Address.from_pointer (
				Gum.strip_code_pointer ((void *) detect_module_path));

			Gum.Process.enumerate_modules ((details) => {
				var range = details.range;
				if (our_address >= range.base_address &&
						our_address < range.base_address + range.size) {
					path = details.path;
					return false;
				}
				return true;
			});

			return path;
		}
	}
}
