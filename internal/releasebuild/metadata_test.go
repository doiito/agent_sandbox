package releasebuild

import (
	"strings"
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 1, 987, time.FixedZone("test", 3600))
	actual, fixed, err := Timestamp("", now)
	if err != nil || fixed || actual.Format(time.RFC3339) != "2026-11-16T11:00:01Z" {
		t.Fatalf("wall time: %v %v %v", actual, fixed, err)
	}
	for _, epoch := range []string{"0", "1794830000", "253402300799"} {
		first, fixed, err := Timestamp(epoch, now)
		second, _, secondErr := Timestamp(epoch, now.Add(time.Hour))
		if err != nil || secondErr != nil || !fixed || first != second {
			t.Fatalf("fixed time %q: %v %v", epoch, first, err)
		}
	}
	for _, epoch := range []string{"-1", "+1", " 1", "1 ", "1.0", "1e2", "253402300800", "99999999999999999999999"} {
		if _, _, err := Timestamp(epoch, now); err == nil {
			t.Fatalf("accepted invalid epoch %q", epoch)
		}
	}
}

func TestSerial(t *testing.T) {
	first, err := Serial([]byte("final document"), true)
	second, secondErr := Serial([]byte("final document"), true)
	changed, _ := Serial([]byte("changed component"), true)
	if err != nil || secondErr != nil || first != second || first == changed || !strings.HasPrefix(first, "urn:uuid:") || first[23] != '5' {
		t.Fatalf("fixed UUIDs: %q %q %q %v", first, second, changed, err)
	}
	left, _ := Serial(nil, false)
	right, _ := Serial(nil, false)
	if left == right || left[23] != '4' || right[23] != '4' {
		t.Fatalf("random UUID behavior changed: %q %q", left, right)
	}
}
