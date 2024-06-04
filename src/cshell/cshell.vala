namespace Frida {
  public class CShellScript : Object {
    public static string get_source () {
			string runtime_js = (string) Frida.Data.Cshell.get_frida_cshell_js_blob ().data;
			return runtime_js;
		}
  }
}
