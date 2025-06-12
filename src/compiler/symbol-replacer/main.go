package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode"
)

var (
	typeRegex = regexp.MustCompile(`type:.eq.(\[\d+\])?([a-z].*)`)
)

type symbl struct {
	symType string
	symVal  string
}

func main() {
	archive := os.Args[1]
	nm := os.Args[2]
	ranlib := strings.Join(os.Args[3:], " ")

	buf := new(bytes.Buffer)
	c := exec.Command(nm, archive)
	c.Stdout = buf
	if err := c.Run(); err != nil {
		panic(err)
	}

	symbols := make(map[string][]string)
	outch := make(chan *symbl, 100)
	inch := make(chan string, 100)
	done := make(chan struct{})

	go func() {
		for s := range outch {
			symbols[s.symType] = append(symbols[s.symType], s.symVal)
		}
		done <- struct{}{}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go parse(inch, outch, &wg)
	}

	content := strings.Split(buf.String(), "\n")
	for _, line := range content {
		splitted := strings.Split(line, " ")
		if len(splitted) >= 3 {
			if strings.ContainsAny(splitted[1], "TSt") {
				inch <- splitted[2]
			}
		}
	}
	close(inch)

	wg.Wait()
	close(outch)
	<-done

	f, err := os.OpenFile(archive, os.O_RDWR, 0755)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	data, _ := io.ReadAll(f)

	for tp, syms := range symbols {
		for _, symbol := range syms {
			switch tp {
			case "simple":
				data = bytes.ReplaceAll(data, []byte(symbol), []byte(flipAlpha(symbol)))
			case "typed":
				toReplace := "type:.eq." + symbol
				splitted := strings.Split(symbol, "=>")
				if len(splitted) == 1 {
					data = bytes.ReplaceAll(data, []byte(toReplace), []byte("type:.eq."+flipAlpha(symbol)))
				} else {
					toReplace = "type:.eq." + splitted[0] + splitted[1]
					flipped := flipAlpha(splitted[1])
					data = bytes.ReplaceAll(data, []byte(toReplace), []byte("type:.eq."+splitted[0]+flipped))
					data = bytes.ReplaceAll(data, []byte(splitted[1]), []byte(flipped))
				}
			}
		}
	}

	data = bytes.ReplaceAll(data, []byte("mingw_vgprintf"), []byte("mingw_vfprintf"))

	f.Truncate(0)
	f.Seek(0, 0)
	f.Write(data)

	ranl := exec.Command(ranlib, archive)
	if err := ranl.Run(); err != nil {
		panic(err)
	}
}

func flipAlpha(s string) string {
	dt := []byte(s)
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if r == 'z' {
				dt[i] = 'a'
			} else if r == 'Z' {
				dt[i] = 'A'
			} else {
				dt[i] = byte(r + 1)
			}
			break
		}
	}
	return string(dt)
}

func parse(inch chan string, outch chan *symbl, wg *sync.WaitGroup) {
	defer wg.Done()
	for symbol := range inch {
		if !strings.ContainsAny(symbol, "/.:") && !strings.Contains(symbol, "frida") {
			outch <- &symbl{symType: "simple", symVal: symbol}
		}
		if strings.Contains(symbol, "type:.eq.") {
			matches := typeRegex.FindStringSubmatch(symbol)
			if len(matches) > 0 {
				val := strings.Join(matches[1:], "=>")
				outch <- &symbl{symType: "typed", symVal: val}
			}
		}
	}
}