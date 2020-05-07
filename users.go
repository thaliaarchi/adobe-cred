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
	r, err := NewTarGZReader(f)
	try(err)
	s := NewRowScanner(r)
	for {
		row, err := s.Row()
		if err == io.EOF {
			break
		}
		try(err)
		_ = row
	}
}

// User contains Adobe account info for a user.
type User struct {
	UID      string
	Username string
	Email    string
	Password string
	Hint     string
}

// NewTarGZReader constructs a reader for a users.tar.gz archive.
func NewTarGZReader(r io.Reader) (*tar.Reader, error) {
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

// RowScanner parses a credential dump into records.
type RowScanner struct {
	br   *bufio.Reader
	Rows int
	Line int
}

func NewRowScanner(r io.Reader) *RowScanner {
	return &RowScanner{bufio.NewReader(r), 0, 0}
}

func (s *RowScanner) Row() (*User, error) {
	var line string
	for line == "" {
		s.Line++
		l, err := s.br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = l[:len(l)-1]
	}

	if !strings.HasSuffix(line, "|--") {
		// Exit if row count encountered
		if strings.HasSuffix(line, " rows selected.") {
			rows, err := strconv.Atoi(line[:len(line)-len(" rows selected.")])
			if err != nil {
				return nil, fmt.Errorf("users: row count parse error: %v", err)
			}
			if rows != s.Rows {
				return nil, fmt.Errorf(`users: dump specifies %d rows, but %d found`, rows, s.Rows)
			}
			return nil, io.EOF
		}

		// Join with the next line to make a complete row
		s.Line++
		next, err := s.br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("users: error on line %d: %v", s.Line, err)
		}
		line += next[:len(next)-1]
		if !strings.HasSuffix(line, "|--") {
			return nil, fmt.Errorf("users: unterminated row on line %d", s.Line)
		}
	}

	line = line[:len(line)-len("|--")]
	row := strings.Split(line, "-|-")
	if len(row) < 5 {
		return nil, fmt.Errorf("users: only %d columns on line %d", len(row), s.Line)
	}
	if len(row) > 5 {
		// A user-inputted field contains the sequence "-|-". In the dump,
		// this only occurs with the hint.
		row[4] = strings.Join(row[4:], "-|-")
		row = row[:5]
	}
	s.Rows++
	return &User{row[0], row[1], row[2], row[3], row[4]}, nil
}

func try(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
