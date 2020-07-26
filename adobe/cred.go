package adobe

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// Cred contains Adobe account info for a user.
type Cred struct {
	UID      int32
	Username string
	Email    string
	Password []byte
	Hint     string
}

// ParseRecord constructs a Cred from the fields of a record.
func ParseRecord(record []string) (*Cred, error) {
	uid, err := strconv.ParseInt(record[0], 10, 32)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(record[3])
	if err != nil {
		return nil, err
	}
	return &Cred{
		int32(uid),
		strings.TrimSpace(record[1]),
		strings.TrimSpace(record[2]),
		b,
		strings.TrimSpace(record[4]),
	}, nil
}
