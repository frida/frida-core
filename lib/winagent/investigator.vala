using Gee;

namespace Zed {
	public class Investigator : Object, Gum.InvocationListener {
		private WinIpc.Proxy proxy;

		private Gum.Stalker stalker = new Gum.Stalker ();
		private uint selected_thread_id;
		private Journal journal;
		private uint send_timeout_id;
		private uint number_of_clues_sent;
		private bool send_in_progress;
		private bool finish_pending;

		public Investigator (WinIpc.Proxy proxy) {
			this.proxy = proxy;
		}

		public extern bool attach (TriggerInfo start_trigger, TriggerInfo stop_trigger);
		public extern void detach ();

		public void on_enter (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * cpu_context, void * function_arguments) {
			if (context.thread_data == null)
				return;

			TriggerType type = (TriggerType) context.instance_data;
			weak Journal journal = (Journal) context.thread_data;

			if ((type & TriggerType.STOP) != 0 && journal.state == Journal.State.OPENED) {
				stalker.unfollow_me ();

				journal.state = Journal.State.SEALED;

				Idle.add (() => {
					end_investigation ();
					return false;
				});
			}
		}

		public void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value) {
			if (context.thread_data == null)
				return;

			TriggerType type = (TriggerType) context.instance_data;
			weak Journal journal = (Journal) context.thread_data;

			if ((type & TriggerType.START) != 0 && journal.state == Journal.State.CREATED) {
				journal.state = Journal.State.OPENED;

				send_timeout_id = Timeout.add (500, () => {
					send_next_batch_of_clues ();
					return true;
				});

				stalker.follow_me (journal);
			}
		}

		public void * provide_thread_data (void * function_instance_data, uint thread_id) {
			lock (journal) {
				if (selected_thread_id == 0 || thread_id == selected_thread_id) {
					selected_thread_id = thread_id;

					if (journal == null)
						journal = new Journal ();

					return (void *) journal;
				}
			}

			return null;
		}

		private async void send_next_batch_of_clues () {
			if (send_in_progress)
				return;

			send_in_progress = true;

			uint count = journal.seen_call_count;

			var builder = new VariantBuilder (new VariantType ("a(i(ssu)(ssu))"));
			for (uint i = number_of_clues_sent; i != count; i++) {
				unowned Gum.CallEvent ev = journal.seen_calls[i];

				var site_addr = FunctionAddress.resolve ((size_t) ev.location);
				var target_addr = FunctionAddress.resolve ((size_t) ev.target);
				if (site_addr != null && target_addr != null) {
					builder.add ("(i(ssu)(ssu))",
						ev.depth,
						site_addr.module_name, site_addr.function_name, site_addr.offset,
						target_addr.module_name, target_addr.function_name, target_addr.offset);
				} else {
					builder.add ("(i(ssu)(ssu))",
						ev.depth,
						"", "", (uint32) ev.location,
						"", "", (uint32) ev.target);
				}
			}

			var result = builder.end ();

			if (result.n_children () != 0) {
				try {
					yield proxy.emit ("NewBatchOfClues", result);
				} catch (WinIpc.ProxyError e) {
					error (e.message);
				}
			}

			number_of_clues_sent = count;

			send_in_progress = false;

			if (finish_pending) {
				finish_pending = false;
				yield send_next_batch_of_clues ();
				yield send_finish_signal ();
			}
		}

		private async void end_investigation () {
			Source.remove (send_timeout_id);
			send_timeout_id = 0;

			if (send_in_progress) {
				finish_pending = true;
				return;
			}

			yield send_next_batch_of_clues ();
			yield send_finish_signal ();
		}

		private async void send_finish_signal () {
			try {
				yield proxy.emit ("InvestigationFinished");
			} catch (WinIpc.ProxyError e) {
				error (e.message);
			}
		}

		private class Journal : Object, Gum.EventSink {
			public enum State {
				CREATED,
				OPENED,
				SEALED
			}

			public State state {
				get;
				set;
			}

			private const uint CAPACITY = 500000;

			public Gum.CallEvent[] seen_calls = new Gum.CallEvent[CAPACITY];
			public uint seen_call_count = 0;

			public Journal () {
				state = State.CREATED;
			}

			public Gum.EventType query_mask () {
				return Gum.EventType.CALL;
			}

			public void process (void * opaque_event) {
				assert (seen_call_count != seen_calls.length);
				Memory.copy (&seen_calls[seen_call_count], opaque_event, sizeof (Gum.CallEvent));
				seen_call_count++;
			}
		}
	}

	public class TriggerInfo {
		public string module_name {
			get;
			private set;
		}

		public string function_name {
			get;
			private set;
		}

		public TriggerInfo (string module_name, string function_name) {
			this.module_name = module_name;
			this.function_name = function_name;
		}
	}

	public enum TriggerType {
		START = 1 << 0,
		STOP  = 1 << 1
	}

	public class FunctionAddress {
		public string module_name {
			get;
			private set;
		}

		public size_t offset {
			get;
			private set;
		}

		public string function_name {
			get;
			set;
		}

		public FunctionAddress (string module_name, size_t offset) {
			this.module_name = module_name;
			this.offset = offset;
			this.function_name = "";
		}

		public extern static FunctionAddress? resolve (size_t address);
	}
}
