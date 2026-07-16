// Command hath runs the Hentai@Home distributed-CDN client.
//
// Usage:
//
//	hath [--data-dir=...] [--cache-dir=...] [--port=...] [--debug]
//
// Credentials: place "<ClientID>-<ClientKey>" in <data-dir>/client_login, or
// set HATH_CLIENT_ID / HATH_CLIENT_KEY. All other settings come from the server.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	_ "time/tzdata"

	"github.com/clickin/hath/internal/hath"
)

func main() {
	args := os.Args[1:]
	if extra := os.Getenv("EXTRA_ARGS"); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	debug := false
	for _, a := range args {
		if a == "--debug" || strings.HasPrefix(a, "--debug=") {
			debug = true
		}
	}

	s := hath.NewSettings()
	s.ParseArgs(args)

	// logging needs the log dir; honor a default before InitDirs resolves it.
	hath.InitLog(debug, s.DisableLogs, s.LogDir)
	hath.ApplyUmaskFromEnv()

	if err := s.InitDirs(); err != nil {
		fmt.Fprintln(os.Stderr, "could not create program directories:", err)
		os.Exit(1)
	}

	hath.Info("Hentai@Home " + hath.ClientVer + " (build " + fmt.Sprint(hath.ClientBuild) + ") starting up")
	hath.Info("Go port of Hentai@Home — GPL-3.0-or-later; original (c) E-Hentai.org / tenboro")

	if err := hath.NewHathClient(s, hath.NewStats()).Run(context.Background()); err != nil {
		hath.Error("fatal", "err", err)
		os.Exit(1)
	}
}
