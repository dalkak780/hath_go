package hath

import "testing"

// TestAuthFormulas pins the exact pre-image and output of every authentication
// token against SHA-1 vectors computed independently with shasum(1). If any of
// these break, the client would send malformed RPC payloads → account lockout,
// so this is the one check that must not regress.
func TestAuthFormulas(t *testing.T) {
	const (
		cid = 1234
		key = "abcdefghijklmnopqrst"
	)
	cases := []struct {
		name, got, want string
	}{
		{"actkey",
			actkey("client_login", "", cid, 1700000000, key),
			"41515df11cefbe0d3012a07782e2d6777f7f650a"},
		{"keystamp",
			keystampHash(1700000500, "abcdef0123456789abcdef0123456789abcdef01-12345-jpg", key),
			"855071598e"},
		{"servercmd",
			servercmdKey("still_alive", "", cid, 1700000000, key),
			"4774887af07e1257ed2c1d03a67acda9f2f86ff7"},
		{"speedtest",
			speedtestKey("1000000", 1700000000, cid, key),
			"6f8659dc2e594965122d1f66d7490ceccbdcdedb"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}

func TestHVFileParse(t *testing.T) {
	simple := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-12345-jpg")
	if simple == nil || simple.Hash != "abcdef0123456789abcdef0123456789abcdef01" ||
		simple.Size != 12345 || simple.Type != "jpg" || simple.StaticRange() != "abcd" {
		t.Fatalf("unexpected simple parse: %+v", simple)
	}
	resized := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-12345-640-480-png")
	if resized == nil || resized.Xres != 640 || resized.Yres != 480 || resized.Type != "png" {
		t.Fatalf("unexpected resized parse: %+v", resized)
	}
	if ParseHVFile("nope") != nil {
		t.Fatal("expected nil for invalid fileid")
	}
}

