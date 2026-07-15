// Command rpcverify validates the Go client's RPC against a capture of real
// traffic from a live Java instance (produced by captureproxy).
//
// For every authenticated request in the capture it recomputes the actkey with
// the same SHA-1 formula the Go client uses, and asserts it is byte-identical
// to the actkey the Java client actually sent. It also rebuilds the full query
// string the Go client would emit and diffs it against the captured one. Any
// mismatch means the Go client would send a malformed request — the exact
// condition that locks accounts — so this is the authoritative safety check.
//
// Usage:
//
//	go run ./tools/rpcverify -in rpc_capture.jsonl -login data/client_login
//	# or:  -key <20-char client key>  -cid <client id>
//
// Exit code is non-zero if any authenticated request fails parity.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// actkey mirrors internal/hath.actkey exactly. Its correctness is independently
// pinned by internal/hath/rpc_test.go against shasum(1) vectors, so drift here
// would be caught.
func actkey(act, add, cid, acttime, clientKey string) string {
	pre := fmt.Sprintf("hentai@home-%s-%s-%s-%s-%s", act, add, cid, acttime, clientKey)
	sum := sha1.Sum([]byte(pre))
	return hex.EncodeToString(sum[:]) // lowercase
}

// strictQuery parses a raw query splitting ONLY on '&', preserving ';' inside
// values — matching the real H@H server (and the Go client's raw concatenation).
func strictQuery(rawq string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(rawq, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			out[k] = v
		} else if k != "" {
			out[k] = ""
		}
	}
	return out
}

type record struct {
	URL string `json:"url"`
}

func main() {
	var inPath, loginPath, key, cidStr string
	flag.StringVar(&inPath, "in", "rpc_capture.jsonl", "capture file from captureproxy")
	flag.StringVar(&loginPath, "login", "", "path to client_login ('<id>-<key>')")
	flag.StringVar(&key, "key", "", "20-char client key (overrides -login)")
	flag.StringVar(&cidStr, "cid", "", "client id (overrides -login)")
	flag.Parse()

	if key == "" || cidStr == "" {
		if loginPath == "" {
			loginPath = "data/client_login"
		}
		b, err := os.ReadFile(loginPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "need -login <file> or -key/-cid: %v\n", err)
			os.Exit(2)
		}
		parts := strings.SplitN(strings.TrimSpace(string(b)), "-", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "malformed client_login")
			os.Exit(2)
		}
		cidStr, key = parts[0], parts[1]
	}
	if len(key) != 20 {
		fmt.Fprintf(os.Stderr, "warning: client key is %d chars (expected 20)\n", len(key))
	}

	f, err := os.Open(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open capture:", err)
		os.Exit(2)
	}
	defer f.Close()

	total, authed, matched, mismatched := 0, 0, 0, 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	ln := 0
	for scanner.Scan() {
		ln++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: bad record: %v\n", ln, err)
			continue
		}
		total++
		rawq := queryOf(rec.URL)
		if rawq == "" {
			continue
		}
		q := strictQuery(rawq)
		act := q["act"]

		// server_stat is unauthenticated; just confirm it carries no actkey.
		if act == "server_stat" {
			if q["actkey"] != "" {
				fmt.Printf("line %d: WARN server_stat unexpectedly carries actkey\n", ln)
			}
			continue
		}
		if q["actkey"] == "" {
			continue // non-RPC request in the capture (e.g. a download)
		}
		authed++
		want := actkey(act, q["add"], q["cid"], q["acttime"], key)

		// rebuild the query exactly as the Go client would, and diff
		rebuilt := fmt.Sprintf("clientbuild=%s&act=%s&add=%s&cid=%s&acttime=%s&actkey=%s",
			q["clientbuild"], act, q["add"], q["cid"], q["acttime"], want)
		urlParity := rebuilt == rawq

		switch {
		case want == q["actkey"] && urlParity:
			matched++
		default:
			mismatched++
			fmt.Printf("line %d: MISMATCH act=%s\n", ln, act)
			fmt.Printf("  captured actkey: %s\n", q["actkey"])
			fmt.Printf("  recomputed     : %s\n", want)
			if !urlParity {
				fmt.Printf("  query also differs:\n    captured: %s\n    rebuilt : %s\n", rawq, rebuilt)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
	}

	fmt.Printf("\n=== rpcverify summary ===\n")
	fmt.Printf("records: %d, authenticated RPC: %d, parity OK: %d, mismatches: %d\n",
		total, authed, matched, mismatched)
	if authed > 0 && mismatched == 0 {
		fmt.Printf("PASS: every captured actkey matches the Go formula byte-for-byte.\n")
		return
	}
	if mismatched > 0 {
		fmt.Printf("FAIL: %d request(s) would be malformed — DO NOT ship until fixed.\n", mismatched)
		os.Exit(1)
	}
	fmt.Println("no authenticated RPC requests found in capture")
}

// queryOf extracts the raw query (after '?') from a possibly-absolute URL.
func queryOf(u string) string {
	i := strings.Index(u, "?")
	if i < 0 {
		return ""
	}
	return u[i+1:]
}
