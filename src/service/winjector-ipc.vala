namespace Zed.Service.WinjectorIpc {
	public const string INJECT_SIGNATURE = "(us)";
	public const string INJECT_RESPONSE = "(bus)";
	public delegate void InjectFunc (uint32 process_id, string dll_path) throws WinjectorError;

	public Variant? marshal_inject (Variant? arg, InjectFunc func) {
		uint32 process_id;
		string dll_path;
		arg.get (INJECT_SIGNATURE, out process_id, out dll_path);

		bool success = true;
		uint32 error_code = 0;
		string error_message = "";

		try {
			func (process_id, dll_path);
		} catch (WinjectorError e) {
			success = false;
			error_code = e.code;
			error_message = e.message;
		}

		return new Variant (INJECT_RESPONSE, success, error_code, error_message);
	}

	public async void invoke_inject (uint32 target_pid, string filename, WinIpc.Proxy proxy) throws WinjectorError {
		Variant response;

		try {
			response = yield proxy.query ("Inject", new Variant (INJECT_SIGNATURE, target_pid, filename), INJECT_RESPONSE);
		} catch (WinIpc.ProxyError e) {
			throw new WinjectorError.FAILED (e.message);
		}

		bool success;
		uint error_code;
		string error_message;
		response.get (INJECT_RESPONSE, out success, out error_code, out error_message);
		if (!success) {
			var permission_error = new WinjectorError.PERMISSION_DENIED (error_message);
			if (error_code == permission_error.code)
				throw permission_error;
			else
				throw new WinjectorError.FAILED (error_message);
		}
	}
}
