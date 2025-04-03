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

		public abstract async void deallocate (Cancellable? cancellable) throws Error, IOError;
	}

	public sealed class SimpleAllocator : Object, Allocator {
		public size_t page_size {
			get { return _page_size; }
		}

		private Machine machine;
		private size_t _page_size;
		private uint64 base_pa;

		private uint64 cursor;

		public SimpleAllocator (Machine machine, size_t page_size, uint64 base_pa) {
			this.machine = machine;
			this._page_size = page_size;
			this.base_pa = base_pa;
			this.cursor = base_pa;
		}

		public async Allocation allocate (size_t size, size_t alignment, Cancellable? cancellable) throws Error, IOError {
			if (base_pa == 0) {
				uint64 example_base;
				if ("corellium" in machine.gdb.features)
					example_base = 0x0800000000 + ((2048 - 3) * 1024 * 1024);
				else
					example_base = 0x0040000000 + (128 * 1024 * 1024);
				throw new Error.NOT_SUPPORTED ("To enable this feature, set FRIDA_BAREBONE_HEAP_BASE to the physical " +
					"base address to use, e.g. 0x%" + uint64.FORMAT_MODIFIER + "x", example_base);
			}

			uint64 address_pa = cursor;

			size_t vm_size = round_size_up (size, page_size);
			cursor += vm_size;

			uint num_pages = (uint) (vm_size / page_size);

			Allocation page_allocation = yield machine.allocate_pages (address_pa, num_pages, cancellable);

			return new SimpleAllocation (page_allocation);
		}

		private class SimpleAllocation : Object, Allocation {
			public uint64 virtual_address {
				get { return page_allocation.virtual_address; }
			}

			private Allocation page_allocation;

			public SimpleAllocation (Allocation page_allocation) {
				this.page_allocation = page_allocation;
			}

			public async void deallocate (Cancellable? cancellable) throws Error, IOError {
				// TODO: Add to freelist.
				yield page_allocation.deallocate (cancellable);
			}
		}
	}
}
