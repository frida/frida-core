namespace Zed {
	public class Configuration : Object {
		public string config_dir {
			get;
			construct;
		}

		private static Configuration? default_config;

		private KeyFile accounts;
		private string accounts_filename;
		private string? accounts_etag = null;
		private Gee.Map<string, Account> accounts_map;

		private bool sync_scheduled = false;

		construct {
			accounts = new KeyFile ();
			accounts_filename = Path.build_filename (config_dir, "Frida", "accounts.ini");
			accounts_map = new Gee.HashMap<string, Account> (str_hash, str_equal);

			try {
				accounts.load_from_file (accounts_filename, KeyFileFlags.NONE);
			} catch (KeyFileError e) {
				warning (e.message);
			} catch (FileError e) {
				warning (e.message);
			}
		}

		public Configuration (string config_dir) {
			Object (config_dir: config_dir);
		}

		public static Configuration get_default () {
			if (Configuration.default_config == null) {
				var config_dir = Environment.get_user_config_dir ();
				Configuration.default_config = new Configuration (config_dir);
			}

			return Configuration.default_config;
		}

		public Account? get_default_account () {
			try {
				string account_name = accounts.get_string ("DEFAULT", "account");
				if (account_name != null) {
					return get_account (account_name);
				} else {
					return null;
				}
			} catch (KeyFileError e) {
				return null;
			}
		}

		public bool set_default_account (Account account) {
			if (accounts.has_group (account.name)) {
				accounts.set_string ("DEFAULT", "account", account.name);
				sync ();
				return true;
			}

			return false;
		}

		public Account get_account (string name) {
			Account account = accounts_map.@get (name);
			if (account == null) {
				account = new Account (accounts, name);
				account.notify.connect (sync);
				accounts_map.@set (name, account);
			}

			return account;
		}

		private void sync () {
			if (sync_scheduled)
				return;

			Idle.add (() => {
				var accounts_file = File.new_for_path (accounts_filename);
				var accounts_dir = accounts_file.get_parent ();

				size_t data_length;
				string data = accounts.to_data (out data_length);

				try {
					if (!accounts_dir.query_exists (null))
						accounts_dir.make_directory_with_parents (null);
					accounts_file.replace_contents (data, data_length, accounts_etag, false, FileCreateFlags.PRIVATE,
						out accounts_etag, null);
				} catch (Error e) {
					warning (e.message);
				}

				sync_scheduled = false;
				return false;
			});
			sync_scheduled = true;
		}

		public class Account : Object {
			public weak KeyFile accounts {
				private get;
				construct;
			}

			public string name {
				get;
				construct;
			}

			public string? password {
				get {
					try {
						var encoded_password = accounts.get_string (name, "password");
						_password = decode_password (encoded_password);
					} catch (KeyFileError e) {
					}

					return _password;
				}

				set {
					var encoded_password = encode_password (value);
					accounts.set_string (name, "password", encoded_password);
				}
			}
			private string? _password;

			public Account (KeyFile accounts, string name) {
				Object (accounts: accounts, name: name);
			}

			private string encode_password (string s) {
				uint8 key = get_password_key ();
				uint8[] tmp = new uint8[s.length];
				for (int i = 0; i != tmp.length; i++)
					tmp[i] = ((uint8) s[i]) ^ key;
				return Base64.encode (tmp);
			}

			private string decode_password (string s) {
				uint8 key = get_password_key ();
				uint8[] tmp = Base64.decode (s);
				for (int i = 0; i != tmp.length; i++)
					tmp[i] ^= key;
				return (string) tmp;
			}

			private uint8 get_password_key () {
				return (uint8) name.length;
			}
		}
	}
}
