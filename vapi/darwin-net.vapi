[CCode (cheader_filename = "net/if.h", lower_case_cprefix = "", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.Net {
	public const int IFNAMSIZ;

	public unowned string? if_indextoname (uint ifindex, [CCode (array_length = false)] char[] ifname);
}
