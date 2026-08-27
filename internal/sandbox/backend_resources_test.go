package sandbox

import "testing"

func TestIOMaxValue(t *testing.T) {
	if got, want := ioMaxValue("8:2", 104857600, 52428800), "8:2 rbps=104857600 wbps=52428800"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestValidBlockDeviceID(t *testing.T) {
	for _, value := range []string{"8:0", "253:12", "0:0"} {
		if !validBlockDeviceID(value) {
			t.Fatalf("valid device id %q rejected", value)
		}
	}
	for _, value := range []string{"", "8", "8:0:1", "-1:0", "8:x"} {
		if validBlockDeviceID(value) {
			t.Fatalf("invalid device id %q accepted", value)
		}
	}
}
