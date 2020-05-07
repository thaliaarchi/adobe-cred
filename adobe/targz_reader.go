package adobe

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
)

// NewUsersTarGZReader constructs a reader for a users.tar.gz archive.
func NewUsersTarGZReader(r io.Reader) (*tar.Reader, error) {
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
