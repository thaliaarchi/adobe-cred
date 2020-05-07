package adobe

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// User contains Adobe account info for a user.
type User struct {
	UID      int32
	Username string
	Email    string
	Password string
	Hint     string
}

// ParseRecord constructs a User from the fields of a record.
func ParseRecord(record []string) (*User, error) {
	uid, err := strconv.ParseInt(record[0], 10, 32)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(record[3])
	if err != nil {
		return nil, err
	}
	return &User{
		int32(uid),
		strings.TrimSpace(record[1]),
		strings.TrimSpace(record[2]),
		hex.EncodeToString(b),
		strings.TrimSpace(record[4]),
	}, nil
}
