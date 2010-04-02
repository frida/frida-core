public static void main (string[] args) {
	Test.init (ref args);

	test_winjector_add_tests ();

	Test.run ();
}
