[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public async Allocation inject_elf (Gum.ElfModule elf, Machine machine, Allocator allocator, Cancellable? cancellable)
			throws Error, IOError {
		size_t vm_size = (size_t) elf.mapped_size;

		size_t page_size = yield machine.query_page_size (cancellable);
		uint num_pages = (uint) (vm_size / page_size);
		if (vm_size % page_size != 0)
			num_pages++;

		var allocation = yield allocator.allocate (num_pages * page_size, page_size, cancellable);
		try {
			uint64 base_va = allocation.virtual_address;

			Bytes relocated_image = machine.relocate (elf, base_va);
			yield machine.gdb.write_byte_array (base_va, relocated_image, cancellable);

			yield machine.protect_pages (base_va, vm_size, READ | EXECUTE, cancellable);
		} catch (GLib.Error e) {
			yield allocation.deallocate (cancellable);
			throw_api_error (e);
		}

		return allocation;
	}
}
