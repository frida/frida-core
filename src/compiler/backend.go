package main

import "C"

//export BundleJS
func BundleJS(entry *C.char) *C.char {
	return C.CString("w00t")
}

func main() {}
