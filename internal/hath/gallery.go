package hath

// GalleryDownloader is a faithful port of the original GalleryDownloader. It
// polls the server's download queue (/15/dl? act=fetchqueue), parses gallery
// metadata, downloads every file (SHA-1 verified) into the download dir, and
// reports distinct failures back to the server. It runs in its own goroutine
// and stops when the client shuts down.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GalleryDownloader polls and executes gallery download jobs.
type GalleryDownloader struct {
	client       *HathClient
	rpc          *ServerHandler
	settings     *Settings
	stats        *Stats
	limiter      *BandwidthMonitor

	gid      int
	filecount int
	minxres  string
	title    string
	info     string
	files    []*galleryFile
	todir    string

	pending bool
	marked  bool
	failures []string
}

var (
	titleStripRe = regexp.MustCompile(`[\*\"\\<>:|?]`)
	wsCollapseRe = regexp.MustCompile(`\s+`)
)

// gallerySleep wraps time.Sleep so tests can stub the (potentially long)
// backoff sleeps without slowing the suite. Mirrors certRefreshSleep.
var gallerySleep = func(d time.Duration) { time.Sleep(d) }

// NewGalleryDownloader starts the downloader goroutine.
func NewGalleryDownloader(c *HathClient) *GalleryDownloader {
	g := &GalleryDownloader{
		client: c, rpc: c.rpc, settings: c.settings, stats: c.stats,
	}
	if !c.settings.DisableDownloadBWM {
		g.limiter = NewBandwidthMonitor(c.settings.ThrottleBytes)
	}
	go g.loop()
	return g
}

func (g *GalleryDownloader) loop() {
	downloadsAvailable := true
	for !g.client.IsShuttingDown() && downloadsAvailable {
		if !g.pending {
			g.pending = g.fetchMeta()
		}
		if !g.pending {
			downloadsAvailable = false
			break
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					Error("gallery downloader: panic processing gallery; skipping", "title", g.title, "err", r)
				}
			}()
			Info("gallery downloader: starting gallery", "title", g.title)

			galleryretry := 0
		totalFailed := 0
		success := false
		for !success && galleryretry < 10 && totalFailed < g.filecount*2 {
			galleryretry++
			successful := 0
			for _, gf := range g.files {
				if g.client.IsShuttingDown() {
					break
				}
				var sleep time.Duration
				switch gf.download(g) {
				case dlOK, dlAlready:
					successful++
					if gf.state == dlOK {
						sleep = time.Second
					}
				case dlFailed:
					totalFailed++
					sleep = 5 * time.Second
				}
				if g.client.IsSuspended() {
					sleep = 60 * time.Second
				} else if g.downloadDirLowSpace() {
					Warn("gallery downloader: paused, low disk space")
					sleep = 5 * time.Minute
				}
				if sleep > 0 {
					gallerySleep(sleep)
				}
			}
			if successful == g.filecount {
				success = true
			}
		}
			g.finalize(success)
		}()
	}
	Info("gallery downloader: thread finished")
	g.client.gallery = nil
}

func (g *GalleryDownloader) downloadDirLowSpace() bool {
	if g.settings.SkipFreeSpaceCheck {
		return false
	}
	return diskFree(g.settings.DownloadDir) < g.settings.DiskMinRemaining+1048576000
}

// fetchMeta marks the previous gallery done and fetches the next one's metadata.
func (g *GalleryDownloader) fetchMeta() bool {
	if g.marked && g.failures != nil {
		g.rpc.ReportDownloaderFailures(g.failures)
	}
	add := ""
	if g.marked {
		add = strconv.Itoa(g.gid) + ";" + g.minxres
	}
	meta := strings.TrimSpace(g.rpc.FetchQueue(add))
	if meta == "" || meta == "INVALID_REQUEST" || meta == "NO_PENDING_DOWNLOADS" {
		return false
	}
	return g.parseMeta(meta)
}

// parseMeta parses the gallery metadata blob. Format:
//
//	GID <n>
//	FILECOUNT <n>
//	MINXRES <v>
//	TITLE <t>
//	FILELIST
//	<page> <fileindex> <xres> <sha1|unknown> <filetype> <filename>
//	...
//	INFORMATION
//	<free text>
func (g *GalleryDownloader) parseMeta(meta string) bool {
	g.reset()
	state := 0
	for _, line := range strings.Split(meta, "\n") {
		if line == "FILELIST" && state == 0 {
			state = 1
			continue
		}
		if line == "INFORMATION" && state == 1 {
			state = 2
			continue
		}
		if state < 2 && line == "" {
			continue
		}
		switch state {
		case 0:
			k, v, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			switch k {
			case "GID":
				g.gid, _ = strconv.Atoi(v)
			case "FILECOUNT":
				g.filecount, _ = strconv.Atoi(v)
			case "MINXRES":
				if xresRe.MatchString(v) {
					g.minxres = v
				} else {
					return false
				}
			case "TITLE":
				g.setTitle(v)
			}
		case 1:
			gf := parseGalleryFile(line)
			if gf != nil {
				g.files = append(g.files, gf)
			}
		case 2:
			if g.info != "" {
				g.info += "\n"
			}
			g.info += line
		}
	}
	return g.gid > 0 && g.filecount > 0 && g.minxres != "" && g.title != "" && g.todir != "" && len(g.files) > 0
}

func (g *GalleryDownloader) setTitle(raw string) {
	t := wsCollapseRe.ReplaceAllString(titleStripRe.ReplaceAllString(raw, ""), " ")
	t = strings.TrimSpace(t)
	xresTitle := ""
	if g.minxres != "org" {
		xresTitle = "-" + g.minxres + "x"
	}
	postfix := " [" + strconv.Itoa(g.gid) + xresTitle + "]"
	maxLen := g.settings.MaxFilenameLen

	runes := []rune(t)
	// 1) rune/UTF-16-unit budget (parity with the original Java client)
	budget := maxLen - len([]rune(postfix))
	if budget < 0 {
		budget = 0
	}
	truncated := len(runes) > budget
	if truncated {
		// reserve 3 runes for the ellipsis, matching the original Java client's
		// codePointCount(0, maxFilenameLength - postfixLength - 3)
		budget -= 3
		if budget < 0 {
			budget = 0
		}
		runes = runes[:budget]
	}
	// 2) hard 255-byte filesystem limit, rune-safe. Unix/ZFS (and most
	// filesystems) cap a name at 255 *bytes*, not characters. The Java client
	// sized by UTF-16 units (default 125) and so a long multi-byte (e.g. CJK)
	// title blew past 255 bytes, hit ENAMETOOLONG, and fell back to an ASCII
	// name — surfacing as "failed to create unicode filename" on Linux/ZFS.
	// Go has no charset problem (names are native UTF-8) but would hit the same
	// byte overflow, so re-truncate rune-safely to keep the unicode name. The
	// ellipsis (added only when truncated) is counted in the byte budget.
	const maxNameBytes = 255
	ellipsis := ""
	if truncated {
		ellipsis = "..."
	}
	for len([]byte(string(runes)+ellipsis+postfix)) > maxNameBytes && len(runes) > 0 {
		runes = runes[:len(runes)-1]
	}
	t = string(runes) + ellipsis
	dir := filepath.Join(g.settings.DownloadDir, t+postfix)
	// traversal guard: parent must be the download dir
	if filepath.Dir(dir) != g.settings.DownloadDir {
		Warn("gallery downloader: unexpected download location")
		dir = filepath.Join(g.settings.DownloadDir, strconv.Itoa(g.gid)+xresTitle)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		Warn("gallery downloader: could not create dir; using fallback")
		dir = filepath.Join(g.settings.DownloadDir, strconv.Itoa(g.gid)+xresTitle)
		os.MkdirAll(dir, 0o755)
	}
	g.todir = dir
	g.title = t
}

func (g *GalleryDownloader) reset() {
	g.gid = 0
	g.filecount = 0
	g.minxres = ""
	g.title = ""
	g.info = ""
	g.files = nil
	g.todir = ""
	g.failures = nil
}

func (g *GalleryDownloader) finalize(success bool) {
	g.pending = false
	g.marked = true
	if success {
		Info("gallery downloader: finished gallery", "title", g.title)
		if err := os.WriteFile(filepath.Join(g.todir, "galleryinfo.txt"), []byte(g.info), 0o644); err != nil {
			Warn("gallery downloader: could not write galleryinfo.txt")
		}
	} else {
		Warn("gallery downloader: permanently failed gallery", "title", g.title)
	}
}

func (g *GalleryDownloader) logFailure(host, fileindex, xres string) {
	fail := host + "-" + fileindex + "-" + xres
	for _, f := range g.failures {
		if f == fail {
			return
		}
	}
	g.failures = append(g.failures, fail)
}

// --- gallery file ---

const (
	dlFailed  = iota
	dlOK
	dlAlready
)

type galleryFile struct {
	page, fileindex int
	xres            string
	sha1            string // "" if unknown
	filetype        string
	filename        string
	state           int
	fileretry       int
}

func parseGalleryFile(line string) *galleryFile {
	parts := strings.SplitN(line, " ", 6)
	if len(parts) != 6 {
		return nil
	}
	page, _ := strconv.Atoi(parts[0])
	idx, _ := strconv.Atoi(parts[1])
	sha1 := parts[3]
	if sha1 == "unknown" {
		sha1 = ""
	}
	return &galleryFile{
		page: page, fileindex: idx, xres: parts[2],
		sha1: sha1, filetype: parts[4], filename: parts[5],
	}
}

func (gf *galleryFile) path(g *GalleryDownloader) string {
	return filepath.Join(g.todir, gf.filename+"."+gf.filetype)
}

func (gf *galleryFile) download(g *GalleryDownloader) int {
	dest := gf.path(g)
	if fi, err := os.Stat(dest); err == nil && fi.Size() > 0 {
		if gf.sha1 == "" || validateFileSHA1(dest, gf.sha1) {
			gf.state = dlAlready
			return gf.state
		}
		os.Remove(dest)
	}
	gf.fileretry++
	source := g.rpc.GetDownloaderFetchURL(g.gid, gf.page, gf.fileindex, gf.xres, gf.fileretry)
	if source == "" {
		gf.state = dlFailed
		return gf.state
	}
	if _, err := g.rpc.DownloadToFile(source, dest, 5*time.Minute, gf.fileretry > 1, false, g.limiter, ""); err != nil {
		Warn("gallery downloader: download error", "file", gf.filename, "err", err)
		gf.state = dlFailed
		g.logFailure(hostOf(source), strconv.Itoa(gf.fileindex), gf.xres)
		return gf.state
	}
	if gf.sha1 != "" && !validateFileSHA1(dest, gf.sha1) {
		Debug("gallery downloader: corrupt download; will retry", "file", gf.filename)
		os.Remove(dest)
		gf.state = dlFailed
		return gf.state
	}
	gf.state = dlOK
	if g.stats != nil {
		g.stats.FileRcvd() // approximates fileRcvd
	}
	Info("gallery downloader: downloaded file", "gid", g.gid, "page", gf.page, "name", gf.filename+"."+gf.filetype)
	return gf.state
}
