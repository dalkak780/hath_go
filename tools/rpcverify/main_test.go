package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func recLine(t *testing.T, url string) string {
	t.Helper()
	b, err := json.Marshal(record{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestRpcVerifyPassAndFail(t *testing.T) {
	dir := t.TempDir()
	loginPath := filepath.Join(dir, "client_login")
	os.WriteFile(loginPath, []byte("1234-abcdefghijklmnopqrst"), 0o644)
	key := "abcdefghijklmnopqrst"

	// good capture: server_stat (unauth) + two authenticated requests, one with
	// a ';' literal inside add (srfetch), all with correct actkeys.
	goodURL1 := "http://rpc.hentaiathome.net/15/rpc?clientbuild=178&act=server_stat"
	goodURL2 := "http://1.2.3.4/15/rpc?clientbuild=178&act=client_login&add=&cid=1234&acttime=1700000000&actkey=" +
		actkey("client_login", "", "1234", "1700000000", key)
	goodURL3 := "http://1.2.3.4/15/rpc?clientbuild=178&act=srfetch&add=5;org;abcdef-1-jpg&cid=1234&acttime=1700000000&actkey=" +
		actkey("srfetch", "5;org;abcdef-1-jpg", "1234", "1700000000", key)
	goodCap := filepath.Join(dir, "good.jsonl")
	os.WriteFile(goodCap, []byte(recLine(t, goodURL1)+recLine(t, goodURL2)+recLine(t, goodURL3)), 0o644)

	if out, code := runVerify(t, goodCap, loginPath); code != 0 || !strings.Contains(out, "PASS") {
		t.Fatalf("good capture should PASS (exit 0):\n%s", out)
	}

	// bad capture: same as goodURL2 but a tampered actkey → must FAIL.
	badURL := "http://1.2.3.4/15/rpc?clientbuild=178&act=client_login&add=&cid=1234&acttime=1700000000&actkey=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	badCap := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(badCap, []byte(recLine(t, badURL)), 0o644)
	out, code := runVerify(t, badCap, loginPath)
	if code == 0 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "MISMATCH") {
		t.Fatalf("bad capture should FAIL (exit!=0) and report MISMATCH:\n%s", out)
	}
}

func runVerify(t *testing.T, cap, login string) (string, int) {
	t.Helper()
	cmd := exec.Command("go", "run", ".", "-in", cap, "-login", login)
	cmd.Dir = "."
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("go run rpcverify: %v\n%s", err, buf.String())
	}
	return buf.String(), code
}
