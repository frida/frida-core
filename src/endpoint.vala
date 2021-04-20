namespace Frida {
	public class EndpointParameters : Object {
		public string? address {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public AuthenticationService? auth_service {
			get;
			construct;
		}

		public EndpointParameters (string? address = null, uint16 port = 0, TlsCertificate? certificate = null,
				AuthenticationService? auth_service = null) {
			Object (
				address: address,
				port: port,
				certificate: certificate,
				auth_service: auth_service
			);
		}
	}
}
