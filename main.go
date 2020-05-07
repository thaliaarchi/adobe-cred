package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/andrewarchi/adobe-users/adobe"
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

	s := adobe.NewUserReader(r)
	for {
		record, err := s.Read()
		if err == io.EOF {
			break
		}
		try(err)
		user, err := adobe.ParseRecord(record)
		try(err)
		fmt.Printf("%s\t%s\n", user.Password, user.Hint)
	}
}

func try(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
