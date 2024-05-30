[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	using Darwin.GCD;
	using Darwin.DNSSD;
	using Darwin.Net;

	public class DarwinPairingBrowser : Object, PairingBrowser {
		private MainContext main_context;
		private DispatchQueue dispatch_queue = new DispatchQueue ("re.frida.fruity.browser-queue", DispatchQueueAttr.SERIAL);

		private DNSService dns_connection;
		private DNSService browse_session;
		private TaskQueue task_queue;

		private Gee.List<PairingServiceDetails> current_batch = new Gee.ArrayList<PairingServiceDetails> ();

		construct {
			main_context = MainContext.ref_thread_default ();

			dispatch_queue.dispatch_async (() => {
				DNSService.create_connection (out dns_connection);
				dns_connection.set_dispatch_queue (dispatch_queue);

				DNSService session = dns_connection;
				DNSService.browse (ref session, PrivateFive | ShareConnection, 0, PAIRING_REGTYPE, PAIRING_DOMAIN,
					on_browse_reply);
				browse_session = session;

				task_queue = new TaskQueue (this);
			});
		}

		~DarwinPairingBrowser () {
			dispatch_queue.dispatch_sync (() => {
				browse_session.deallocate ();
				dns_connection.deallocate ();
			});
		}

		private void on_browse_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
				DNSService.ErrorType error_code, string service_name, string regtype, string reply_domain) {
			if (error_code != NoError)
				return;

			var interface_name_buf = new char[IFNAMSIZ];
			unowned string interface_name = if_indextoname (interface_index, interface_name_buf);

			var service = new DarwinPairingServiceDetails (service_name, interface_index, interface_name, task_queue);
			current_batch.add (service);

			if ((flags & DNSService.Flags.MoreComing) != 0)
				return;

			var services = current_batch;
			current_batch = new Gee.ArrayList<PairingServiceDetails> ();

			schedule_on_frida_thread (() => {
				services_discovered (services.to_array ());
				return Source.REMOVE;
			});
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class TaskQueue : Object, DNSServiceProvider {
			private weak DarwinPairingBrowser parent;

			private DNSServiceTask? current = null;
			private Gee.Deque<DNSServiceTask> pending = new Gee.ArrayQueue<DNSServiceTask> ();

			public TaskQueue (DarwinPairingBrowser parent) {
				this.parent = parent;
			}

			private async T with_dns_service<T> (DNSServiceTask task, Cancellable? cancellable) throws Error, IOError {
				var promise = new Promise<Object> ();
				task.set_data ("promise", promise);
				pending.offer_tail (task);

				maybe_start_next ();

				return (T) yield promise.future.wait_async (cancellable);
			}

			private void maybe_start_next () {
				if (current != null)
					return;

				DNSServiceTask? task = pending.poll_head ();
				if (task == null)
					return;
				current = task;

				parent.dispatch_queue.dispatch_async (() => {
					current.dns_connection = parent.dns_connection;
					current.on_complete = on_complete;
					current.start ();
				});
			}

			private void on_complete (Object? result, Error? error) {
				parent.schedule_on_frida_thread (() => {
					Promise<Object> promise = current.steal_data ("promise");

					if (error != null)
						promise.reject (error);
					else
						promise.resolve (result);

					current = null;
					maybe_start_next ();

					return Source.REMOVE;
				});
			}
		}
	}

	private interface DNSServiceProvider : Object {
		public abstract async T with_dns_service<T> (DNSServiceTask task, Cancellable? cancellable) throws Error, IOError;
	}

	private abstract class DNSServiceTask : Object {
		internal DNSService? dns_connection;
		internal CompleteFunc? on_complete;

		protected DNSService? session;

		public delegate void CompleteFunc (Object? result, Error? error);

		public abstract void start ();

		protected void complete (Object? result, Error? error) {
			if (session != null && session != dns_connection) {
				session.deallocate ();
				session = null;
			}

			on_complete (result, error);
			on_complete = null;
		}
	}

	public class DarwinPairingServiceDetails : Object, PairingServiceDetails {
		public string name {
			get { return _name; }
		}

		public uint interface_index {
			get { return _interface_index; }
		}

		public string interface_name {
			get { return _interface_name; }
		}

		private string _name;
		private uint _interface_index;
		private string _interface_name;

		private DNSServiceProvider dns;

		internal DarwinPairingServiceDetails (string name, uint interface_index, string interface_name, DNSServiceProvider dns) {
			_name = name;
			_interface_index = interface_index;
			_interface_name = interface_name;

			this.dns = dns;
		}

		public async Gee.List<PairingServiceHost> resolve (Cancellable? cancellable) throws Error, IOError {
			var task = new ResolveTask (this);
			return yield dns.with_dns_service (task, cancellable);
		}

		private class ResolveTask : DNSServiceTask {
			private weak DarwinPairingServiceDetails parent;

			private Gee.List<PairingServiceHost> hosts = new Gee.ArrayList<PairingServiceHost> ();

			public ResolveTask (DarwinPairingServiceDetails parent) {
				this.parent = parent;
			}

			public override void start () {
				session = dns_connection;
				DNSService.resolve (ref session, PrivateFive | ShareConnection, parent.interface_index, parent.name,
					PAIRING_REGTYPE, PAIRING_DOMAIN, on_resolve_reply);
			}

			private void on_resolve_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
					DNSService.ErrorType error_code, string fullname, string hosttarget, uint16 port,
					uint8[] raw_txt_record) {
				if (error_code != NoError) {
					complete (null,
						new Error.TRANSPORT ("Unable to resolve service '%s' on interface %s",
							parent.name, parent.interface_name));
					return;
				}

				var txt_record = new Gee.ArrayList<string> ();
				size_t cursor = 0;
				size_t remaining = raw_txt_record.length;
				while (remaining != 0) {
					size_t len = raw_txt_record[cursor];
					cursor++;
					remaining--;
					if (len > remaining)
break;

					unowned string raw_val = (string) raw_txt_record[cursor:cursor + len];
					string val = raw_val.make_valid ((ssize_t) len);
					txt_record.add (val);

					cursor += len;
					remaining -= len;
				}

				hosts.add (new DarwinPairingServiceHost (parent, hosttarget, uint16.from_big_endian (port), txt_record,
					parent.dns));

				if ((flags & DNSService.Flags.MoreComing) == 0)
					complete (hosts, null);
			}
		}
	}

	public class DarwinPairingServiceHost : Object, PairingServiceHost {
		public string name {
			get { return _name; }
		}

		public uint16 port {
			get { return _port; }
		}

		public Gee.List<string> txt_record {
			get { return _txt_record; }
		}

		private string _name;
		private uint16 _port;
		private Gee.List<string> _txt_record;

		private PairingServiceDetails service;
		private DNSServiceProvider dns;

		internal DarwinPairingServiceHost (PairingServiceDetails service, string name, uint16 port, Gee.List<string> txt_record,
				DNSServiceProvider dns) {
			_name = name;
			_port = port;
			_txt_record = txt_record;

			this.service = service;
			this.dns = dns;
		}

		public async Gee.List<InetSocketAddress> resolve (Cancellable? cancellable) throws Error, IOError {
			var task = new ResolveTask (this);
			return yield dns.with_dns_service (task, cancellable);
		}

		private class ResolveTask : DNSServiceTask {
			private weak DarwinPairingServiceHost parent;

			private Gee.List<InetSocketAddress> addresses = new Gee.ArrayList<InetSocketAddress> ();

			public ResolveTask (DarwinPairingServiceHost parent) {
				this.parent = parent;
			}

			public override void start () {
				session = dns_connection;
				DNSService.get_addr_info (ref session, PrivateFive | ShareConnection, parent.service.interface_index, IPv6,
					parent.name, on_info_reply);
			}

			private void on_info_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
					DNSService.ErrorType error_code, string hostname, void * address, uint32 ttl) {
				if (error_code != NoError) {
					complete (null,
						new Error.TRANSPORT ("Unable to resolve host '%s' on interface %s",
							parent.name, parent.service.interface_name));
					return;
				}

				addresses.add ((InetSocketAddress) SocketAddress.from_native (address, sizeof (Posix.SockAddrIn6)));

				if ((flags & DNSService.Flags.MoreComing) == 0)
					complete (addresses, null);
			}
		}
	}
}
