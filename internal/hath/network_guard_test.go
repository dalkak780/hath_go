package hath

import (
	"context"
	"fmt"
	"net"
)

// Tests may bind local mocks but must never contact the production RPC service.
func init() {
	localDialer := &net.Dialer{}
	outboundDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("external network disabled in tests: %s", address)
		}
		return localDialer.DialContext(ctx, network, address)
	}
}
