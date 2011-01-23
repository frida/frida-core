public class Zed.StorageBackend : Object {
	private KeyFile keyfile = new KeyFile ();
	private string keyfile_path = Path.build_filename (get_data_directory (), "zed.dat");
	private string? keyfile_etag;

	private const string DEFAULT_GROUP_NAME = "zed";

	public StorageBackend () {
		try {
			keyfile.load_from_file (keyfile_path, KeyFileFlags.NONE);
		} catch (KeyFileError kfe) {
		} catch (FileError fe) {
		}
	}

	public Variant? read (string key) {
		try {
			var blob = new BinaryBlob.from_base64 (keyfile.get_string (DEFAULT_GROUP_NAME, key));
			return Variant.new_from_data (VariantType.VARIANT, blob.data, true, blob).get_variant ();
		} catch (KeyFileError kfe) {
			return null;
		}
	}

	public void write (string key, Variant val) {
		var box = new Variant.variant (val);
		uchar[] bytes = new uchar[box.get_size ()];
		box.store ((void *) bytes);
		keyfile.set_string (DEFAULT_GROUP_NAME, key, Base64.encode (bytes));
		sync ();
	}

	public void forget (string key) {
		try {
			keyfile.remove_key (DEFAULT_GROUP_NAME, key);
			sync ();
		} catch (KeyFileError kfe) {
		}
	}

	private void sync () {
		size_t data_length;
		var data = keyfile.to_data (out data_length);

		var file = File.new_for_path (keyfile_path);

		try {
			file.replace_contents (data, data_length, keyfile_etag, false, FileCreateFlags.PRIVATE, out keyfile_etag, null);
		} catch (Error e) {
		}
	}

	private class BinaryBlob {
		public uchar[] data;

		public BinaryBlob.from_base64 (string base64_value) {
			data = Base64.decode (base64_value);
		}
	}

	public static extern string get_data_directory ();
}
