[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public interface Allocator : Object {
		public abstract size_t page_size {
			get;
		}

		public abstract async Allocation allocate (size_t size, size_t alignment, Cancellable? cancellable)
			throws Error, IOError;
	}

	public interface Allocation : Object {
		public abstract uint64 virtual_address {
			get;
		}

		public abstract size_t size {
			get;
		}

		public abstract async void deallocate (Cancellable? cancellable) throws Error, IOError;
	}

	public sealed class NullAllocator : Object, Allocator {
		public size_t page_size {
			get {
				return _page_size;
			}
		}

		private size_t _page_size;

		public NullAllocator (size_t page_size) {
			this._page_size = page_size;
		}

		public async Allocation allocate (size_t size, size_t alignment, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("To enable this feature, specify an allocator in your FRIDA_BAREBONE_CONFIG");
		}
	}

	public sealed class PhysicalAllocator : Object, Allocator {
		public size_t page_size {
			get {
				return _page_size;
			}
		}

		private Machine machine;
		private size_t _page_size;

		private uint64 cursor;

		public PhysicalAllocator (Machine machine, size_t page_size, PhysicalAllocatorConfig config) {
			this.machine = machine;
			this._page_size = page_size;
			this.cursor = config.physical_base.address;
		}

		public async Allocation allocate (size_t size, size_t alignment, Cancellable? cancellable) throws Error, IOError {
			uint64 address_pa = cursor;

			size_t vm_size = round_size_up (size, _page_size);
			cursor += vm_size;

			uint num_pages = (uint) (vm_size / _page_size);

			Allocation page_allocation = yield machine.allocate_pages (address_pa, num_pages, cancellable);

			return new PhysicalAllocation (page_allocation);
		}

		private class PhysicalAllocation : Object, Allocation {
			public uint64 virtual_address {
				get {
					return page_allocation.virtual_address;
				}
			}

			public size_t size {
				get {
					return page_allocation.size;
				}
			}

			private Allocation page_allocation;

			public PhysicalAllocation (Allocation allocation) {
				page_allocation = allocation;
			}

			public async void deallocate (Cancellable? cancellable) throws Error, IOError {
				// TODO: Add to freelist.
				yield page_allocation.deallocate (cancellable);
			}
		}
	}

	public sealed class TargetFunctionsAllocator : Object, Allocator {
		public size_t page_size {
			get {
				return _page_size;
			}
		}

		private Machine machine;
		private size_t _page_size;
		private TargetFunctionsAllocatorConfig config;

		public TargetFunctionsAllocator (Machine machine, size_t page_size, TargetFunctionsAllocatorConfig config) {
			this.machine = machine;
			this._page_size = page_size;
			this.config = config;
		}

		public async Allocation allocate (size_t size, size_t alignment, Cancellable? cancellable) throws Error, IOError {
			uint64 address = yield machine.invoke (config.alloc_function.address, { size }, cancellable);

			// TODO: Handle alignment.

			return new TargetAllocation (address, size, machine, config);
		}

		private class TargetAllocation : Object, Allocation {
			public uint64 virtual_address {
				get {
					return _virtual_address;
				}
			}

			public size_t size {
				get {
					return _size;
				}
			}

			private uint64 _virtual_address;
			public size_t _size;
			private Machine machine;
			private TargetFunctionsAllocatorConfig config;

			public TargetAllocation (uint64 address, size_t size, Machine m, TargetFunctionsAllocatorConfig c) {
				_virtual_address = address;
				_size = size;
				machine = m;
				config = c;
			}

			public async void deallocate (Cancellable? cancellable) throws Error, IOError {
				yield machine.invoke (config.free_function.address, { _virtual_address, size }, cancellable);
			}
		}
	}
}
