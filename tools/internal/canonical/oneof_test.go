package canonical

import (
	"encoding/hex"
	"testing"
)

func TestOneofPinsTheProtoTagAndPayloadFrame(t *testing.T) {
	got, err := Oneof(4, []byte{1, 2})
	if err != nil || hex.EncodeToString(got) != "0000000400000000000000020102" {
		t.Fatal("oneof differs from the canonical byte vector", err)
	}
	for _, tag := range []uint64{0, 1 << 29} {
		if _, err := Oneof(tag, []byte{1}); err == nil {
			t.Fatal("invalid proto field number admitted")
		}
	}
	if _, err := Oneof(4); err == nil {
		t.Fatal("absent selected payload admitted")
	}
}
