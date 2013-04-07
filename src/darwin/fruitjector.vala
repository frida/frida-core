#if DARWIN
using Gee;

namespace Frida {
	public class Fruitjector : Object {
		public signal void uninjected (uint id);

		private HashMap<string, TemporaryFile> agents = new HashMap<string, TemporaryFile> ();

		/* these should be private, but must be accessible to glue code */
		private MainContext main_context;
		public void * context;
		public Gee.HashMap<uint, void *> instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		construct {
			main_context = MainContext.get_thread_default ();
			_create_context ();
		}

		~Fruitjector () {
			foreach (var tempfile in agents.values)
				tempfile.destroy ();
			foreach (var instance in instance_by_id.values)
				_free_instance (instance);
			_destroy_context ();
		}

		public async uint inject (uint pid, AgentDescriptor desc, string data_string) throws IOError {
			var agent = agents[desc.name];
			if (agent == null) {
				agent = new TemporaryFile.from_stream (desc.name, desc.dylib);
				agents[desc.name] = agent;
			}

			return _do_inject (pid, agent.path, data_string);
		}

		public bool any_still_injected () {
			return !instance_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return instance_by_id.has_key (id);
		}

		public void _on_instance_dead (uint id) {
			var source = new IdleSource ();
			source.set_callback (() => {
				void * instance;
				bool instance_id_found = instance_by_id.unset (id, out instance);
				assert (instance_id_found);
				_free_instance (instance);
				uninjected (id);
				return false;
			});
			source.attach (main_context);
		}

		public extern void _create_context ();
		public extern void _destroy_context ();
		public extern void _free_instance (void * instance);
		public extern uint _do_inject (uint pid, string dylib_path, string data_string) throws IOError;
	}

	public class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream dylib {
			get {
				reset_stream (_dylib);
				return _dylib;
			}

			construct {
				_dylib = value;
			}
		}
		private InputStream _dylib;

		public AgentDescriptor (string name, InputStream dylib) {
			Object (name: name, dylib: dylib);

			assert (dylib is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (Error e) {
				assert_not_reached ();
			}
		}
	}
}
#endif
