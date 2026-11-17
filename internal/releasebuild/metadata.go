// Package releasebuild provides reproducible metadata for release generators.
// It is not used by the running API, launcher, or guest.
package releasebuild

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func Timestamp(epoch string, now time.Time) (time.Time, bool, error) {
	if epoch == "" {
		return now.UTC().Truncate(time.Second), false, nil
	}
	for _, digit := range epoch {
		if digit < '0' || digit > '9' {
			return time.Time{}, false, errors.New("SOURCE_DATE_EPOCH must be nonnegative whole Unix seconds")
		}
	}
	seconds, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || seconds > 253402300799 {
		return time.Time{}, false, errors.New("SOURCE_DATE_EPOCH exceeds the RFC3339 range")
	}
	return time.Unix(seconds, 0).UTC(), true, nil
}

// Serial uses UUIDv5 for fixed builds and the prior random UUIDv4 otherwise.
// SHA-1 is the UUIDv5 naming algorithm, not an artifact integrity check.
func Serial(document []byte, fixed bool) (string, error) {
	var value [16]byte
	if fixed {
		// RFC namespace OID: 6ba7b812-9dad-11d1-80b4-00c04fd430c8.
		namespace := []byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
		hash := sha1.New()
		hash.Write(namespace)
		hash.Write(document)
		copy(value[:], hash.Sum(nil))
		value[6] = value[6]&0x0f | 0x50
	} else {
		if _, err := rand.Read(value[:]); err != nil {
			return "", err
		}
		value[6] = value[6]&0x0f | 0x40
	}
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
