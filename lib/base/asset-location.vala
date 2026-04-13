namespace Frida {
	public class AssetLocation : Object {
		public string libdir {
			get;
			construct;
		}

		public static AssetLocation detect () {
			string? module_path = null;
			Gum.Address our_address = Gum.Address.from_pointer (Gum.strip_code_pointer ((void *) detect));

			Gum.Process.enumerate_modules ((details) => {
				var range = details.range;
				if (our_address >= range.base_address && our_address < range.base_address + range.size) {
					module_path = details.path;
					return false;
				}
				return true;
			});

			assert (module_path != null);
			return new AssetLocation (Path.get_dirname (module_path));
		}

		private AssetLocation (string libdir) {
			Object (libdir: libdir);
		}

		public string derive_asset_path (string arch, string filename) {
			return Path.build_filename (libdir, Config.FRIDA_LIBDIR_NAME, arch, filename);
		}

		public string derive_plugin_path (string filename) {
			return Path.build_filename (libdir, Config.FRIDA_LIBDIR_NAME, "plugins", filename);
		}
	}
}
