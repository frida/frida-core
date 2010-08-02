using Gee;

namespace Zed {
	public class MemoryTracker : Object {
		private WinIpc.Proxy proxy;
		private uint begin_handler_id;
		private uint end_handler_id;
		private uint peek_handler_id;

		private Gum.InstanceTracker instance_tracker;

		public MemoryTracker (WinIpc.Proxy proxy) {
			this.proxy = proxy;
			register_query_handlers ();
		}

		~MemoryTracker () {
			instance_tracker = null;

			unregister_query_handlers ();
		}

		private void register_query_handlers () {
			begin_handler_id = proxy.register_query_sync_handler ("BeginInstanceTrace", "", (arg) => {
				if (instance_tracker == null) {
					Gum.InstanceVTable vtable;
					if (!find_vtable (out vtable))
						return Ipc.SimpleResult.failure ("gobject library not found");
					instance_tracker = new Gum.InstanceTracker ();
					instance_tracker.begin (vtable);
					return Ipc.SimpleResult.ok ();
				} else {
					return Ipc.SimpleResult.failure ("trace already in progress");
				}
			});

			end_handler_id = proxy.register_query_sync_handler ("EndInstanceTrace", "", (arg) => {
				if (instance_tracker != null) {
					instance_tracker.end ();
					instance_tracker = null;
					return Ipc.SimpleResult.ok ();
				} else {
					return Ipc.SimpleResult.failure ("no trace in progress");
				}
			});

			peek_handler_id = proxy.register_query_sync_handler ("PeekInstances", "", (arg) => {
				var result = new VariantBuilder (new VariantType ("(ba(tus))"));

				var entries = new VariantBuilder (new VariantType ("a(tus)"));

				if (instance_tracker != null) {
					result.add ("b", true);
					instance_tracker.walk_instances ((id) => {
						entries.add ("(tus)", (uint64) id.address, id.ref_count, id.type_name);
					});
				} else {
					result.add ("b", false);
				}

				result.add_value (entries.end ());

				return result.end ();
			});
		}

		private void unregister_query_handlers () {
			proxy.unregister_query_handler (begin_handler_id);
			proxy.unregister_query_handler (end_handler_id);
			proxy.unregister_query_handler (peek_handler_id);
		}

		private bool find_vtable (out Gum.InstanceVTable vtable) {
			Gum.InstanceVTable vt = Gum.InstanceVTable ();

			Gum.Process.enumerate_modules ((name, address, path) => {
				string match = name.str ("gobject-2.0");
				if (match == null)
					return true;

				vt.create_instance = Gum.Module.find_export_by_name (name, "g_type_create_instance");
				vt.free_instance = Gum.Module.find_export_by_name (name, "g_type_free_instance");
				vt.type_id_to_name = Gum.Module.find_export_by_name (name, "g_type_name");
				return false;
			});

			bool success = vt.create_instance != null && vt.free_instance != null && vt.type_id_to_name != null;
			if (success)
				vtable = vt;

			return success;
		}
	}
}
