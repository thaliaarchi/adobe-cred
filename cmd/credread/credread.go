package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/andrewarchi/adobe-cred/adobe"
)

func main() {
	var filename string
	if len(os.Args) >= 2 {
		filename = os.Args[1]
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "%s not found\n", filename)
			os.Exit(2)
		}
	} else if _, err := os.Stat("cred"); err == nil {
		filename = "cred"
	} else if _, err := os.Stat("users.tar.gz"); err == nil {
		filename = "users.tar.gz"
	} else {
		fmt.Fprintln(os.Stderr, "cred or users.tar.gz not found")
		os.Exit(2)
	}

	f, err := os.Open(filename)
	try(err)
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		tr, err := adobe.NewUsersTarGZReader(f)
		try(err)
		r = tr
	}

	cr := adobe.NewCredReader(r)
	w := csv.NewWriter(os.Stdout)
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		try(err)
		if _, err := adobe.ParseRecord(record); err != nil {
			fmt.Fprintln(os.Stderr, err, record)
		}
		try(w.Write(record))
	}
}

func try(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
