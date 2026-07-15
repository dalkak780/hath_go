package hath

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestRPCActionFailures exercises the not-OK branches of the URL-based actions
// (the Info/Debug failure-log paths), which return nil/empty.
func TestRPCActionFailures(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActStaticRangeFetch, "FAIL_NO_SUCH_FILE\n")
	m.setResponse(ActDownloaderFetch, "FAIL_X\n")
	m.setResponse(ActGetBlacklist, "TEMPORARILY_UNAVAILABLE\n")

	if urls := rpc.GetStaticRangeFetchURL("1", "org", "abcdef-1-jpg"); urls != nil {
		t.Fatalf("srfetch should return nil on FAIL, got %v", urls)
	}
	if u := rpc.GetDownloaderFetchURL(1, 1, 1, "org", 1); u != "" {
		t.Fatalf("dlfetch should return empty on FAIL, got %q", u)
	}
	if bl := rpc.GetBlacklist(0); bl != nil {
		t.Fatalf("blacklist should return nil on non-OK, got %v", bl)
	}
}

// TestRPCReportFailuresStatusLog hits the Debug status-log branch in
// ReportDownloaderFailures (response != OK).
func TestRPCReportFailuresStatusLog(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActDownloaderFailRep, "FAIL\n")
	rpc.ReportDownloaderFailures([]string{"a;b"})
	// no assertion beyond exercising the not-OK Debug path
}

// TestWalkRangeDirsWithFilesAndNonDirs covers the skip-non-dir branches.
func TestWalkRangeDirsWithFilesAndNonDirs(t *testing.T) {
	root := t.TempDir()
	// a stray file directly at root (skipped by the l1 isDir check)
	writeFile(t, filepath.Join(root, "loosefile"), []byte("x"))
	// a range dir with a file and a nested subdir (subdir skipped)
	writeFile(t, filepath.Join(root, "ab", "cd", "f1"), []byte("y"))
	os.MkdirAll(filepath.Join(root, "ab", "cd", "sub"), 0o755)
	// an empty l2 dir
	os.MkdirAll(filepath.Join(root, "ab", "ef"), 0o755)

	visited := 0
	walkRangeDirs(root, func(l1, l2 string, files []os.DirEntry) {
		visited++
	})
	if visited == 0 {
		t.Fatal("expected at least one range dir visit")
	}
}

// TestServercmdRefreshSettingsAndCerts: the refresh_settings / refresh_certs
// servercmds invoke the client triggers (coverage for those switch arms).
func TestServercmdRefreshSettingsAndCerts(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()

	for _, cmd := range []string{"refresh_settings", "refresh_certs", "start_downloader"} {
		key := servercmdKey(cmd, "", s.ClientID, t0, s.ClientKey)
		target := "/servercmd/" + cmd + "//" + itoa(int(t0)) + "/" + key
		resp, err := http.Get(srv.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: expected 200, got %d", cmd, resp.StatusCode)
		}
	}
}
