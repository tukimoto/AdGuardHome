package dnsforward

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/ipset"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// ipsetCtx is the ipset context.  ipsetMgr can be nil.
type ipsetCtx struct {
	ipsetMgr ipset.Manager
	logger   *slog.Logger
}

// newIPSetCtx returns a new initialized [ipsetCtx].  It is not safe for
// concurrent use.
func newIPSetCtx(logger *slog.Logger, ipsetConf []string) (c *ipsetCtx, err error) {
	c = &ipsetCtx{
		logger: logger,
	}
	ipsetLogger := logger.With(slogutil.KeyPrefix, "ipset")
	c.ipsetMgr, err = ipset.NewManager(ipsetLogger, ipsetConf)
	if errors.Is(err, os.ErrInvalid) || errors.Is(err, os.ErrPermission) {
		// ipset cannot currently be initialized if the server was installed
		// from Snap or when the user or the binary doesn't have the required
		// permissions, or when the kernel doesn't support netfilter.
		//
		// Log and go on.
		//
		// TODO(a.garipov): The Snap problem can probably be solved if we add
		// the netlink-connector interface plug.
		logger.Warn("ipset: cannot initialize", slogutil.KeyError, err)

		return c, nil
	} else if errors.Is(err, errors.ErrUnsupported) {
		logger.Warn("ipset: cannot initialize", slogutil.KeyError, err)

		return c, nil
	} else if err != nil {
		return nil, fmt.Errorf("initializing ipset: %w", err)
	}

	return c, nil
}

// close closes the Linux Netfilter connections.
func (c *ipsetCtx) close() (err error) {
	if c.ipsetMgr != nil {
		return c.ipsetMgr.Close()
	}

	return nil
}

func (c *ipsetCtx) dctxIsfilled(dctx *dnsContext) (ok bool) {
	return dctx != nil &&
		dctx.responseFromUpstream &&
		dctx.proxyCtx != nil &&
		dctx.proxyCtx.Res != nil &&
		dctx.proxyCtx.Req != nil &&
		len(dctx.proxyCtx.Req.Question) > 0
}

// skipIpsetProcessing returns true when the ipset processing can be skipped for
// this request.
func (c *ipsetCtx) skipIpsetProcessing(dctx *dnsContext) (ok bool) {
	if c == nil || c.ipsetMgr == nil || !c.dctxIsfilled(dctx) {
		return true
	}

	qtype := dctx.proxyCtx.Req.Question[0].Qtype

	return qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeANY
}

// ipFromRR returns an IP address from a DNS resource record.
func ipFromRR(rr dns.RR) (ip net.IP) {
	switch a := rr.(type) {
	case *dns.A:
		return a.A
	case *dns.AAAA:
		return a.AAAA
	default:
		return nil
	}
}

// ipsFromAnswer returns IPv4 and IPv6 addresses from a DNS answer.
func ipsFromAnswer(ans []dns.RR) (ip4s, ip6s []net.IP) {
	for _, rr := range ans {
		ip := ipFromRR(rr)
		if ip == nil {
			continue
		}

		if ip.To4() == nil {
			ip6s = append(ip6s, ip)

			continue
		}

		ip4s = append(ip4s, ip)
	}

	return ip4s, ip6s
}

// process adds the resolved IP addresses to the domain's ipsets, if any.
func (c *ipsetCtx) process(dctx *dnsContext) (rc resultCode) {
	c.logger.Debug("ipset: started processing")
	defer c.logger.Debug("ipset: finished processing")

	if c.skipIpsetProcessing(dctx) {
		return resultCodeSuccess
	}

	req := dctx.proxyCtx.Req
	host := req.Question[0].Name
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)

	ip4s, ip6s := ipsFromAnswer(dctx.proxyCtx.Res.Answer)
	n, err := c.ipsetMgr.Add(host, ip4s, ip6s)
	if err != nil {
		// Consider ipset errors non-critical to the request.
		c.logger.Error("ipset: adding host ips", slogutil.KeyError, err)

		return resultCodeSuccess
	}

	c.logger.Debug("ipset: added new ipset entries", "num", n)

	return resultCodeSuccess
}
