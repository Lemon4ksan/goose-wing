// urloracle: Go net/url reference oracle for scripts/url_differential.py.
//
// Reads a batch file (path in argv[1], or stdin) with lines:
//
//	P\t<hex_raw>
//	R\t<hex_base>\t<hex_ref>
//
// Outputs one line per input:
//
//	ERR
//	OK\t<scheme>\t<user>\t<pass>\t<hostname>\t<port>\t<escaped_path>\t<raw_query>\t<escaped_frag>\t<href>
//
// where each field is lowercase hex or "-" if empty.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func encHex(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func decHex(s string) (string, bool) {
	if s == "-" || s == "" {
		return "", true
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func emitUrl(w *bufio.Writer, u *url.URL) {
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	fmt.Fprintf(w, "OK\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		encHex(u.Scheme),
		encHex(user),
		encHex(pass),
		encHex(u.Hostname()),
		encHex(u.Port()),
		encHex(u.EscapedPath()),
		encHex(u.RawQuery),
		encHex(u.EscapedFragment()),
		encHex(u.String()),
	)
}

func main() {
	in := os.Stdin
	if len(os.Args) >= 2 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "urloracle: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		in = f
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		switch parts[0] {
		case "P":
			if len(parts) < 2 {
				fmt.Fprintln(w, "ERR")
				continue
			}
			raw, ok := decHex(parts[1])
			if !ok {
				fmt.Fprintln(w, "ERR")
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				fmt.Fprintln(w, "ERR")
				continue
			}
			emitUrl(w, u)
		case "R":
			if len(parts) < 3 {
				fmt.Fprintln(w, "ERR")
				continue
			}
			baseRaw, ok1 := decHex(parts[1])
			refRaw, ok2 := decHex(parts[2])
			if !ok1 || !ok2 {
				fmt.Fprintln(w, "ERR")
				continue
			}
			base, err := url.Parse(baseRaw)
			if err != nil {
				fmt.Fprintln(w, "ERR")
				continue
			}
			u, err := base.Parse(refRaw)
			if err != nil {
				fmt.Fprintln(w, "ERR")
				continue
			}
			emitUrl(w, u)
		default:
			fmt.Fprintln(w, "ERR")
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "urloracle: %v\n", err)
		os.Exit(2)
	}
}
