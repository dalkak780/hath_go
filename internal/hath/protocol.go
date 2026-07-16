// Package hath implements the Hentai@Home distributed-CDN client.
//
// This is a Go port of Hentai@Home by E-Hentai.org / tenboro, originally
// licensed under GPLv3. Protocol constants and authentication formulas are
// preserved verbatim for wire compatibility.
package hath

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Wire-protocol constants. These MUST match the values the server expects;
// changing them breaks compatibility (and, for auth-related ones, risks
// account lockouts from malformed requests).
const (
	// Keep these in lockstep with hath_java's Settings.CLIENT_BUILD and
	// Settings.CLIENT_VERSION. ClientBuild is the server compatibility level;
	// do not increment it for Go-only releases.
	ClientBuild  = 178
	ClientVer    = "1.6.5"
	ClientKeyLen = 20

	// MaxKeyTimeDrift is the largest tolerated |localServerTime - stampTime|.
	MaxKeyTimeDrift = 300
	TCPPacketSize   = 1460

	ClientRPCProtocol = "http://"
	ClientRPCHost     = "rpc.hentaiathome.net"

	defaultRPCPath = "15/rpc?"

	// keystamp tolerance for /h/ file requests.
	keystampTolerance = 900
)

// RPC actions.
const (
	ActServerStat        = "server_stat"
	ActGetBlacklist      = "get_blacklist"
	ActGetCertificate    = "get_cert"
	ActClientLogin       = "client_login"
	ActClientSettings    = "client_settings"
	ActClientStart       = "client_start"
	ActClientSuspend     = "client_suspend"
	ActClientResume      = "client_resume"
	ActClientStop        = "client_stop"
	ActStillAlive        = "still_alive"
	ActStaticRangeFetch  = "srfetch"
	ActDownloaderFetch   = "dlfetch"
	ActDownloaderFailRep = "dlfails"
	ActOverload          = "overload"
)

// sha1Hex returns the lowercase hex SHA-1 of s. This is the primitive behind
// every authentication token in the protocol (actkey, keystamp, servercmd key,
// speedtest key). It MUST stay byte-for-byte identical to Java's
// Tools.getSHA1String.
func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:]) // already lowercase
}

// actkey authenticates an outbound RPC request.
//
//	actkey = sha1("hentai@home-" + act + "-" + add + "-" + clientID + "-" + acttime + "-" + clientKey)
func actkey(act, add string, clientID int, acttime int64, clientKey string) string {
	return sha1Hex(fmt.Sprintf("hentai@home-%s-%s-%d-%d-%s", act, add, clientID, acttime, clientKey))
}

// keystampHash returns the 10-char hex prefix used to validate /h/ hotlink tokens.
//
//	prefix = sha1(keystampTime + "-" + fileid + "-" + clientKey + "-hotlinkthis")[:10]
func keystampHash(keystampTime int64, fileid, clientKey string) string {
	return sha1Hex(fmt.Sprintf("%d-%s-%s-hotlinkthis", keystampTime, fileid, clientKey))[:10]
}

// servercmdKey validates an inbound /servercmd request.
//
//	key = sha1("hentai@home-servercmd-" + cmd + "-" + add + "-" + clientID + "-" + time + "-" + clientKey)
func servercmdKey(cmd, add string, clientID int, t int64, clientKey string) string {
	return sha1Hex(fmt.Sprintf("hentai@home-servercmd-%s-%s-%d-%d-%s", cmd, add, clientID, t, clientKey))
}

// speedtestKey validates an inbound /t speedtest request.
//
//	key = sha1("hentai@home-speedtest-" + size + "-" + time + "-" + clientID + "-" + clientKey)
func speedtestKey(size string, t int64, clientID int, clientKey string) string {
	return sha1Hex(fmt.Sprintf("hentai@home-speedtest-%s-%d-%d-%s", size, t, clientID, clientKey))
}

// fileid format: <40-hex>-<size>[-<xres>-<yres>]-<type>
var (
	fileidRe2 = regexp.MustCompile(`^[a-f0-9]{40}-[0-9]{1,10}-(jpg|png|gif|mp4|wbm|wbp|avf|jxl)$`)
	fileidRe5 = regexp.MustCompile(`^[a-f0-9]{40}-[0-9]{1,10}-[0-9]{1,5}-[0-9]{1,5}-(jpg|png|gif|mp4|wbm|wbp|avf|jxl)$`)
)

// mime types for hvfile types.
var hvMime = map[string]string{
	"jpg": "image/jpeg",
	"png": "image/png",
	"gif": "image/gif",
	"mp4": "video/mp4",
	"wbm": "video/webm",
	"wbp": "image/webp",
	"avf": "image/avif",
	"jxl": "image/jxl",
}

// HVFile is a parsed cache file id.
type HVFile struct {
	Hash string
	Size int64
	Xres int
	Yres int
	Type string
}

// Fileid reconstructs the canonical file id.
func (f HVFile) Fileid() string {
	if f.Xres > 0 {
		return fmt.Sprintf("%s-%d-%d-%d-%s", f.Hash, f.Size, f.Xres, f.Yres, f.Type)
	}
	return fmt.Sprintf("%s-%d-%s", f.Hash, f.Size, f.Type)
}

// StaticRange is the 4-char range prefix used for static-range assignment.
func (f HVFile) StaticRange() string { return f.Hash[:4] }

// Mime returns the content type for the file type.
func (f HVFile) Mime() string {
	if m, ok := hvMime[f.Type]; ok {
		return m
	}
	return "application/octet-stream"
}

// ParseHVFile parses and validates a file id. Returns nil if invalid.
func ParseHVFile(fileid string) *HVFile {
	if !fileidRe2.MatchString(fileid) && !fileidRe5.MatchString(fileid) {
		return nil
	}
	parts := strings.Split(fileid, "-")
	hash := parts[0]
	size, _ := strconv.ParseInt(parts[1], 10, 64)
	if size > int64(^uint32(0)>>1) {
		return nil
	}
	f := &HVFile{Hash: hash, Size: size}
	if len(parts) == 3 {
		f.Type = parts[2]
	} else {
		f.Xres, _ = strconv.Atoi(parts[2])
		f.Yres, _ = strconv.Atoi(parts[3])
		f.Type = parts[4]
	}
	return f
}
