package hath

import "testing"

func TestHumanBytes(t *testing.T) {
	for _, test := range []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1 << 20, "1.0 MiB"},
		{1536 << 20, "1.5 GiB"},
	} {
		if got := humanBytes(test.bytes); got != test.want {
			t.Errorf("humanBytes(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
}
