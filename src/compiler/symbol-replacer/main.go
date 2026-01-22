package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"runtime"
	"unicode"
)

var (
	excludeSymbols = [][]byte{
		[]byte("fprintf"),
		[]byte("pthread"),
		[]byte("cas"),
	}
)

func main() {
	archive := os.Args[1]
	nm := os.Args[2]
	ranlib := os.Args[3]
	cc := os.Args[4]

	buf := new(bytes.Buffer)
	c := exec.Command(nm, archive)
	c.Stdout = buf
	if err := c.Run(); err != nil {
		panic(err)
	}

	t := newTrie()
	t.insert([]byte("internal/"), flipAlpha([]byte("internal/")))

	var content [][]byte

	if runtime.GOOS == "windows" {
		if strings.Contains(cc, "clangarm64") {
			content = bytes.Split(buf.Bytes(), []byte{'\n'})
		} else {
			content = bytes.Split(buf.Bytes(), []byte("\r\n"))
		}
	} else {
		content = bytes.Split(buf.Bytes(), []byte{'\n'})
	}

	for _, line := range content {
		splitted := bytes.Split(line, []byte{' '})
		if len(splitted) >= 3 {
			symbolType := splitted[1]
			symbol := splitted[2]
			symbolLower := bytes.ToLower(symbol)

			if bytes.ContainsAny(symbolType, "TSt") {
				if symbolIsOkay(symbolLower) {
					t.insert(symbol, flipAlpha(symbol))
				}
			} else if bytes.ContainsAny(symbolType, "Rrd") {
				if bytes.HasPrefix(symbolLower, []byte("go:")) {
					t.insert(symbol, flipAlpha(symbol))
				}
			}
		}
	}

	f, err := os.OpenFile(archive, os.O_RDWR, 0755)
	if err != nil {
		panic(err)
	}

	data, _ := io.ReadAll(f)
	modifiedData := make([]byte, len(data))

	for i := 0; i < len(data); {
		if l, replacement, ok := t.search(data, i); ok {
			copy(modifiedData[i:], replacement)
			i += l
		} else {
			modifiedData[i] = data[i]
			i++
		}
	}

	f.Truncate(0)
	f.Seek(0, 0)
	f.Write(modifiedData)

	f.Close()

	ranl := exec.Command(ranlib, archive)
	if err := ranl.Run(); err != nil {
		panic(err)
	}
}

func flipAlpha(s []byte) []byte {
	dt := make([]byte, len(s))
	copy(dt, s)

	for i, r := range s {
		if unicode.IsLetter(rune(r)) || unicode.IsNumber(rune(r)) {
			if r == 'z' {
				dt[i] = 'a'
			} else if r == 'Z' {
				dt[i] = 'A'
			} else {
				dt[i] = r + 1
			}
			break
		}
	}
	return dt
}

func symbolIsOkay(symbol []byte) bool {
	switch {
	case bytes.Contains(symbol, []byte("frida")):
		return false
	case bytes.Contains(symbol, []byte("rt0")):
		return true
	case bytes.Contains(symbol, []byte("cgo")):
		return true
	case bytes.ContainsAny(symbol, "./"):
		return true
	default:
		for _, s := range excludeSymbols {
			if bytes.Contains(symbol, s) {
				return false
			}
		}
		return true
	}
}
