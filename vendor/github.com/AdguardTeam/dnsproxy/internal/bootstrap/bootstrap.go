// Package bootstrap provides types and functions to resolve upstream hostnames
// and to dial retrieved addresses.
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// Network is a network type for use in [Resolver]'s methods.
type Network = string

const (
	// NetworkIP is a network type for both address families.
	NetworkIP Network = "ip"

	// NetworkIP4 is a network type for IPv4 address family.
	NetworkIP4 Network = "ip4"

	// NetworkIP6 is a network type for IPv6 address family.
	NetworkIP6 Network = "ip6"

	// NetworkTCP is a network type for TCP connections.
	NetworkTCP Network = "tcp"

	// NetworkUDP is a network type for UDP connections.
	NetworkUDP Network = "udp"
)

// DialHandler is a dial function for creating unencrypted network connections
// to the upstream server.  It establishes the connection to the server
// specified at initialization and ignores the addr.  network must be one of
// [NetworkTCP] or [NetworkUDP].
type DialHandler func(ctx context.Context, network Network, addr string) (conn net.Conn, err error)

// ResolveDialContext returns a DialHandler that uses addresses resolved from u
// using resolver.  l and u must not be nil.
func ResolveDialContext(
	u *url.URL,
	timeout time.Duration,
	r Resolver,
	preferV6 bool,
	l *slog.Logger,
) (h DialHandler, err error) {
	defer func() { err = errors.Annotate(err, "dialing %q: %w", u.Host) }()

	host, port, err := netutil.SplitHostPort(u.Host)
	if err != nil {
		// Don't wrap the error since it's informative enough as is and there is
		// already deferred annotation here.
		return nil, err
	}

	if r == nil {
		return nil, fmt.Errorf("resolver is nil: %w", ErrNoResolvers)
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// TODO(e.burkov):  Use network properly, perhaps, pass it through options.
	ips, err := r.LookupNetIP(ctx, NetworkIP, host)
	if err != nil {
		return nil, fmt.Errorf("resolving hostname: %w", err)
	}

	if preferV6 {
		slices.SortStableFunc(ips, netutil.PreferIPv6)
	} else {
		slices.SortStableFunc(ips, netutil.PreferIPv4)
	}

	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.AddrPortFrom(ip, port).String())
	}

	return NewDialContext(timeout, l, addrs...), nil
}

// NewDialContext returns a DialHandler that dials addrs and returns the first
// successful connection.  At least a single addr should be specified.  l must
// not be nil.
func NewDialContext(timeout time.Duration, l *slog.Logger, addrs ...string) (h DialHandler) {
	addrLen := len(addrs)
	if addrLen == 0 {
		l.Debug("no addresses to dial")

		return func(_ context.Context, _, _ string) (conn net.Conn, err error) {
			return nil, errors.Error("no addresses")
		}
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	return func(ctx context.Context, network Network, _ string) (conn net.Conn, err error) {
		var errs []error

		// Return first succeeded connection.  Note that we're using addrs
		// instead of what's passed to the function.
		for i, addr := range addrs {
			a := l.With("addr", addr)
			a.DebugContext(ctx, "dialing", "idx", i+1, "total", addrLen)

			start := time.Now()
			conn, err = dialer.DialContext(ctx, network, addr)
			elapsed := time.Since(start)
			if err != nil {
				a.DebugContext(ctx, "connection failed", "elapsed", elapsed, slogutil.KeyError, err)
				errs = append(errs, err)

				continue
			}

			a.DebugContext(ctx, "connection succeeded", "elapsed", elapsed)

			return conn, nil
		}

		return nil, errors.Join(errs...)
	}
}
