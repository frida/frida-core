public sealed class Frida.SymbolResolver : Object {
	private Gee.Map<uint, ProcMapsSnapshot> cache = new Gee.HashMap<uint, ProcMapsSnapshot> ();

	public void resolve_addresses (uint pid, uint64[] addresses, AddressResolved on_symbol, ModulesReady on_modules) throws Error {
		var snap = get_snapshot (pid);
		bool refreshed = false;

		var used_index = new Gee.HashMap<string, uint> ();
		var used_modules = new Gee.ArrayList<string> ();

		foreach (var addr in addresses) {
			ProcMapsSnapshot.Mapping? m = snap.find_mapping (addr);

			if (m == null && !refreshed) {
				snap = refresh_snapshot (pid);
				refreshed = true;

				m = snap.find_mapping (addr);
			}

			if (m == null) {
				on_symbol (addr, uint32.MAX, 0);
				continue;
			}

			uint mod_idx;
			if (!used_index.has_key (m.module_id)) {
				mod_idx = used_modules.size;
				used_index[m.module_id] = mod_idx;
				used_modules.add (m.module_id);
			} else {
				mod_idx = used_index[m.module_id];
			}

			uint64 rel64 = (addr - m.start) + m.file_offset;
			uint32 rel32 = (rel64 <= uint32.MAX) ? (uint32) rel64 : 0;

			on_symbol (addr, mod_idx, rel32);
		}

		on_modules (used_modules);
	}

	public delegate void AddressResolved (uint64 address, uint module_index, uint32 rel);
	public delegate void ModulesReady (Gee.List<string> modules);

	private ProcMapsSnapshot get_snapshot (uint pid) throws Error {
		var s = cache[pid];
		if (s == null) {
			s = ProcMapsSnapshot.from_pid (pid);
			cache[pid] = s;
		}
		return s;
	}

	private ProcMapsSnapshot refresh_snapshot (uint pid) throws Error {
		var s = ProcMapsSnapshot.from_pid (pid);
		cache[pid] = s;
		return s;
	}

	public void invalidate (uint32 pid) {
		cache.unset (pid);
	}

	public void clear () {
		cache.clear ();
	}
}
