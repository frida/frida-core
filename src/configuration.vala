namespace Zed {
	public class Configuration : Object {
		public StorageBackend backend {
			get;
			construct;
		}

		private Account account;
		private ulong notify_handler_id;

		construct {
			var variant = backend.read ("account");
			if (variant != null) {
				string name, password;
				variant.@get ("(ss)", out name, out password);
				password = deobfuscate (password, obfuscation_key_from_name (name));

				account = new Account (name, password);
				notify_handler_id = account.notify.connect (sync);
			}
		}

		public Configuration (StorageBackend backend) {
			Object (backend: backend);
		}

		public Account? get_default_account () {
			return account;
		}

		public void set_default_account (Account account) {
			if (this.account != null)
				this.account.disconnect (notify_handler_id);
			this.account = account;
			notify_handler_id = this.account.notify.connect (sync);
			sync ();
		}

		private void sync () {
			if (account != null) {
				var variant = new Variant ("(ss)", account.name,
					obfuscate (account.password, obfuscation_key_from_name (account.name)));
				backend.write ("account", variant);
			} else {
				backend.forget ("account");
			}
		}

		private string obfuscate (string s, uint8 key) {
			uint8[] tmp = new uint8[s.length];
			for (int i = 0; i != tmp.length; i++)
				tmp[i] = ((uint8) s[i]) ^ key;
			return Base64.encode (tmp);
		}

		private string deobfuscate (string s, uint8 key) {
			uint8[] tmp = Base64.decode (s);
			for (int i = 0; i != tmp.length; i++)
				tmp[i] ^= key;
			return (string) tmp;
		}

		private uint8 obfuscation_key_from_name (string name) {
			return (uint8) name.length;
		}

		public class Account : Object {
			public string name {
				get;
				construct;
			}

			public string password {
				get;
				set;
			}

			public Account (string name, string password = "") {
				Object (name: name, password: password);
			}
		}
	}
}
