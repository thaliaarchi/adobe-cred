package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	f, err := os.Open("users.tar.gz")
	try(err)
	defer f.Close()
	r, err := NewTarGzReader(f)
	try(err)
	try(ScanRows(r))
}

// User contains Adobe account info for a user.
type User struct {
	UID      string
	Username string
	Email    string
	Password string
	Hint     string
}

// NewTarGzReader constructs a reader for a users.tar.gz archive.
func NewTarGzReader(r io.Reader) (*tar.Reader, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gr)
	header, err := tr.Next()
	if err != nil {
		return nil, err
	}
	if header.Name != "cred" || header.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("users: archive must contain cred file, got: %s", header.Name)
	}
	return tr, nil
}

// ScanRows parses a credential dump into records.
func ScanRows(r io.Reader) error {
	s := bufio.NewScanner(r)
	count := 0
	var line string
	for i := 1; s.Scan(); i++ {
		line = s.Text()
		if len(line) == 0 {
			continue
		}

		// Join with the next line if it is not a complete row.
		if !strings.HasSuffix(line, "|--") {
			if !s.Scan() {
				break
			}
			line += s.Text()
			if !strings.HasSuffix(line, "|--") {
				if !s.Scan() {
					break
				}
				return fmt.Errorf(`users: row on line %d does not end with "|--"`, i)
			}
			i++
		}

		line = line[:len(line)-3]
		row := strings.Split(line, "-|-")
		if len(row) < 5 {
			return fmt.Errorf("users: row on line %d has only %d columns", i, len(row))
		}
		if len(row) > 5 {
			// A user-inputted field contains the sequence "-|-". In the dump,
			// this only occurs with the hint.
			row[4] = strings.Join(row[4:], "-|-")
			row = row[:5]
		}
		// user := User{row[0], row[1], row[2], row[3], row[4]}
		count++
	}

	if err := s.Err(); err != nil {
		return err
	}

	if !strings.HasSuffix(line, " rows selected.") {
		return fmt.Errorf("users: dump does not end with row count")
	}
	rows := line[:len(line)-len(" rows selected.")]
	rowCount, err := strconv.Atoi(rows)
	if err != nil {
		return fmt.Errorf("users: row count parse error: ")
	}
	if rowCount != count {
		return fmt.Errorf(`users: dump contains %d rows, but %d found`, rowCount, count)
	}
	return nil
}

func try(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
