namespace Zed.Agent {
	public class GLogProbe : Object, Gum.InvocationListener {
		public signal void message (string domain, uint level, string message);

		private Gum.Interceptor interceptor = Gum.Interceptor.obtain ();
		private bool is_attached = false;

		private MatchPattern[] match_patterns = new MatchPattern[0];

		public void add (string pattern, uint levels) throws IOError {
			lock (match_patterns) {
				match_patterns += new MatchPattern (pattern, levels);
			}

			try {
				attach_if_needed ();
			} catch (IOError e) {
				clear ();
				throw new IOError.FAILED (e.message);
			}
		}

		public void clear () throws IOError {
			lock (match_patterns) {
				match_patterns = new MatchPattern[0];
			}

			detach_if_attached ();
		}

		public void on_enter (Gum.InvocationContext context) {
			unowned string log_domain = (string) context.get_nth_argument (0);
			unowned uint log_level = (uint) context.get_nth_argument (1);
			unowned string format = (string) context.get_nth_argument (2);
			unowned va_list args = (va_list) context.get_nth_argument (3);

			if (log_domain == null)
				return;

			bool has_match = false;
			foreach (var mp in match_patterns) {
				if (mp.spec.match_string (log_domain)) {
					has_match = true;
					break;
				}
			}
			if (!has_match)
				return;

			var log_message = format.vprintf (args);
			Idle.add (() => {
				message (log_domain, log_level, log_message);
				return false;
			});
		}

		public void on_leave (Gum.InvocationContext context) {
		}

		private void attach_if_needed () throws IOError {
			if (is_attached)
				return;

			string glib_module_name = null;
			Gum.Process.enumerate_modules ((name, address, path) => {
				if (name.down ().str ("glib-2.0") != null) {
					glib_module_name = name;
					return false;
				}

				return true;
			});

			if (glib_module_name == null)
				throw new IOError.FAILED ("glib library not loaded");

			var function_address = Gum.Module.find_export_by_name (glib_module_name, "g_logv");
			if (function_address == null)
				throw new IOError.FAILED ("g_logv not found");

			interceptor.attach_listener (function_address, this);
			is_attached = true;
		}

		private void detach_if_attached () {
			if (!is_attached)
				return;

			interceptor.detach_listener (this);
			is_attached = false;
		}

		private class MatchPattern {
			public PatternSpec spec;
			public uint levels;

			public MatchPattern (string pattern, uint levels) {
				this.spec = new PatternSpec (pattern);
				this.levels = levels;
			}
		}
	}
}
