package spf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver is the interface for DNS lookups used during SPF evaluation.
// Implement this interface to inject a custom or mock DNS resolver.
type Resolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
	LookupMX(ctx context.Context, domain string) ([]string, error)
	LookupA(ctx context.Context, domain string) ([]net.IP, error)
	LookupAAAA(ctx context.Context, domain string) ([]net.IP, error)
	LookupPTR(ctx context.Context, ip net.IP) ([]string, error)
}

// DNSTimeout is the timeout for individual DNS queries made by DefaultResolver.
// Default is 2 seconds. Adjust for your network conditions.
var DNSTimeout = 2 * time.Second

// DNSServer is the DNS server address used by DefaultResolver, in <ip>:<port> format.
// Default is Google's 8.8.8.8:53. A misconfigured DNSServer will cause SPF checks to return TEMPERROR.
var DNSServer = "8.8.8.8:53"

// DefaultResolver is the package-level Resolver that uses the miekg/dns implementation
// and the DNSServer global variable.
var DefaultResolver Resolver = &dnsResolver{}

// dnsResolver is the default Resolver implementation using miekg/dns.
type dnsResolver struct{}

const maxCNAMEDepth = 10

var errCNAMELoop = fmt.Errorf("CNAME chain exceeds maximum depth of %d", maxCNAMEDepth)

// LookupSPF returns the SPF TXT record for domain.
// If no records or more than one record is found, r is set to None or PermError respectively.
// If the DNS lookup fails, r is TempError.
func LookupSPF(ctx context.Context, domain string) (spf string, r Result) {
	txts, err := (idnaResolver{DefaultResolver}).LookupTXT(ctx, domain)
	if err != nil {
		return "", TempError
	}

	var spfs []string
	for _, txt := range txts {
		if hasPrefixFold(txt, "v=spf1") && (len(txt) == 6 || txt[6] == ' ') {
			spfs = append(spfs, txt)
		}
	}

	switch len(spfs) {
	case 0:
		return "", None
	case 1:
		return spfs[0], Result("")
	default:
		return "", PermError
	}
}

// hasPrefixFold checks if s starts with prefix, case-insensitively.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// LookupTXT returns all TXT records for domain.
func (dr *dnsResolver) LookupTXT(ctx context.Context, d string) ([]string, error) {
	var txt []string
	r, err := dnsQuery(ctx, d, dns.TypeTXT)
	if err != nil {
		return txt, err
	}
	for _, answ := range r.Answer {
		if t, ok := answ.(*dns.TXT); ok {
			txt = append(txt, strings.Join(t.Txt, ""))
		}
	}
	return txt, nil
}

func (dr *dnsResolver) LookupA(ctx context.Context, d string) ([]net.IP, error) {
	return dr.lookupADepth(ctx, d, 0)
}

func (dr *dnsResolver) lookupADepth(ctx context.Context, d string, depth int) ([]net.IP, error) {
	if depth > maxCNAMEDepth {
		return nil, errCNAMELoop
	}
	var ips []net.IP
	r, err := dnsQuery(ctx, d, dns.TypeA)
	if err != nil {
		return ips, err
	}
	for _, answ := range r.Answer {
		switch answ := answ.(type) {
		case *dns.A:
			ips = append(ips, answ.A)
		case *dns.CNAME:
			cnameIPs, err := dr.lookupADepth(ctx, answ.Target, depth+1)
			if err != nil {
				return nil, err
			}
			ips = append(ips, cnameIPs...)
		}
	}
	return ips, nil
}

func (dr *dnsResolver) LookupAAAA(ctx context.Context, d string) ([]net.IP, error) {
	return dr.lookupAAAADepth(ctx, d, 0)
}

func (dr *dnsResolver) lookupAAAADepth(ctx context.Context, d string, depth int) ([]net.IP, error) {
	if depth > maxCNAMEDepth {
		return nil, errCNAMELoop
	}
	var ips []net.IP
	r, err := dnsQuery(ctx, d, dns.TypeAAAA)
	if err != nil {
		return ips, err
	}
	for _, answ := range r.Answer {
		switch answ := answ.(type) {
		case *dns.AAAA:
			ips = append(ips, answ.AAAA)
		case *dns.CNAME:
			cnameIPs, err := dr.lookupAAAADepth(ctx, answ.Target, depth+1)
			if err != nil {
				return nil, err
			}
			ips = append(ips, cnameIPs...)
		}
	}
	return ips, nil
}

func (dr *dnsResolver) LookupMX(ctx context.Context, d string) ([]string, error) {
	return dr.lookupMXDepth(ctx, d, 0)
}

func (dr *dnsResolver) lookupMXDepth(ctx context.Context, d string, depth int) ([]string, error) {
	if depth > maxCNAMEDepth {
		return nil, errCNAMELoop
	}
	var mxs []string
	r, err := dnsQuery(ctx, d, dns.TypeMX)
	if err != nil {
		return mxs, err
	}
	for _, answ := range r.Answer {
		switch answ := answ.(type) {
		case *dns.MX:
			mxs = append(mxs, answ.Mx)
		case *dns.CNAME:
			cnameMXs, err := dr.lookupMXDepth(ctx, answ.Target, depth+1)
			if err != nil {
				return nil, err
			}
			mxs = append(mxs, cnameMXs...)
		}
	}
	return mxs, nil
}

func (dr *dnsResolver) LookupPTR(ctx context.Context, ip net.IP) ([]string, error) {
	var hosts []string
	r, err := dnsQuery(ctx, reverseIPArpa(ip), dns.TypePTR)
	if err != nil {
		return hosts, err
	}
	for _, answ := range r.Answer {
		if p, ok := answ.(*dns.PTR); ok {
			hosts = append(hosts, p.Ptr)
		}
	}
	return hosts, nil
}

func reverseIPArpa(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	// IPv6: expand to full 32 hex nibbles, then reverse
	v6 := ip.To16()
	nibbles := make([]byte, 0, 64)
	for i := 15; i >= 0; i-- {
		nibbles = append(nibbles, "0123456789abcdef"[v6[i]&0xf])
		nibbles = append(nibbles, '.')
		nibbles = append(nibbles, "0123456789abcdef"[v6[i]>>4])
		nibbles = append(nibbles, '.')
	}
	return string(nibbles) + "ip6.arpa."
}

// dnsQuery performs a DNS query with context support, configurable timeout,
// and automatic TCP fallback on truncation.
func dnsQuery(ctx context.Context, d string, t uint16) (r *dns.Msg, err error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetQuestion(dns.Fqdn(d), t)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	c := &dns.Client{
		Timeout: DNSTimeout,
	}

	r, _, err = c.ExchangeContext(ctx, m, DNSServer)
	if err != nil {
		return nil, err
	}

	// TCP fallback on truncation (RFC 5966)
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, DNSServer)
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}
