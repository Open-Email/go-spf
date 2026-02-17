// RFC 7208

package spf

import (
	"context"
	"net"
	"regexp"
	"strings"
)

// Result of SPF check
type Result string

// SPF results
const (
	None            = Result("NONE")
	Neutral         = Result("NEUTRAL")
	Pass            = Result("PASS")
	Fail            = Result("FAIL")
	Softfail        = Result("SOFTFAIL")
	TempError       = Result("TEMPERROR")
	PermError       = Result("PERMERROR")
	internalNoMatch = Result("internalNoMatch")
)

var (
	mDirective = regexp.MustCompile(`(?i)^(\+|\-|\?|\~)?(all|include|a|mx|ptr|ip4|ip6|exists):?(.*)$`)
	mModifier  = regexp.MustCompile(`(?i)^([a-z0-9\-\_\.]+)=(.*)$`)
)

// String representation of Result type
func (r Result) String() string {
	return string(r)
}

// IsSet returns true if Result var is set to some value
func (r Result) IsSet() bool {
	return string(r) != ""
}

// Limits per RFC 7208 §4.6.4
const (
	maxDNSMechanisms  = 10 // max DNS-querying mechanisms per check
	maxMXPTRRecords   = 10 // max MX or PTR records to process per mechanism
	maxVoidLookups    = 2  // max void lookups (NXDOMAIN or empty answers)
	maxRecursionDepth = 10 // defence-in-depth recursion limit
)

type check struct {
	ctx      context.Context
	cnt      int
	voidCnt  int
	depth    int
	resolver Resolver
	helo     string
}

// CheckHost performs an SPF check.
// ip - the IP address of the SMTP client that is emitting the mail, either IPv4 or IPv6.
// domain - the domain that provides the sought-after authorization information; initially, the domain portion of the "MAIL FROM" or "HELO" identity.
// sender - the "MAIL FROM" or "HELO" identity.
// helo - domain from helo, used as sender domain if sender is not specified.
func CheckHost(ctx context.Context, ip net.IP, domain, sender, helo string) Result {
	r, _ := CheckHostWithExplanation(ctx, ip, domain, sender, helo)
	return r
}

// CheckHostWithResolver is like CheckHost but uses the provided Resolver for all DNS lookups.
func CheckHostWithResolver(ctx context.Context, ip net.IP, domain, sender, helo string, r Resolver) Result {
	res, _ := CheckHostWithExplanationAndResolver(ctx, ip, domain, sender, helo, r)
	return res
}

// CheckHostWithExplanation is like CheckHost but also returns the explanation string if the result is Fail.
func CheckHostWithExplanation(ctx context.Context, ip net.IP, domain, sender, helo string) (Result, string) {
	return CheckHostWithExplanationAndResolver(ctx, ip, domain, sender, helo, DefaultResolver)
}

// CheckHostWithExplanationAndResolver is like CheckHostWithResolver but also returns the explanation string.
func CheckHostWithExplanationAndResolver(ctx context.Context, ip net.IP, domain, sender, helo string, r Resolver) (Result, string) {
	if sender == "" {
		sender = "postmaster@" + helo
	}

	c := check{
		ctx:      ctx,
		cnt:      0,
		resolver: r,
		helo:     helo,
	}

	return c.checkHost(ip, domain, sender)
}

func (c *check) lookupSPF(domain string) (string, Result) {
	txts, err := c.resolver.LookupTXT(c.ctx, domain)
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
		// RFC 7208 §4.6.4: count void lookups (no SPF record found)
		c.voidCnt++
		if c.voidCnt > maxVoidLookups {
			return "", PermError
		}
		return "", None
	case 1:
		return spfs[0], Result("")
	default:
		return "", PermError
	}
}

func (c *check) checkHost(ip net.IP, domain, sender string) (Result, string) {
	// Defence-in-depth: limit recursion depth independently of DNS counter
	if c.depth >= maxRecursionDepth {
		return PermError, ""
	}
	c.depth++
	defer func() { c.depth-- }()

	spf, r := c.lookupSPF(domain)
	if r.IsSet() {
		return r, ""
	}

	terms := parseSPF(spf)
	var redirect string
	var explanation string
	var seenRedirect bool
	var seenExp bool

	// Pre-scan for modifiers; RFC 7208 §6 treats modifiers as record-scoped,
	// not positional, so collect them before evaluating directives.
	for _, term := range terms {
		if m, ok := term.(modifier); ok {
			switch strings.ToLower(m.name) {
			case "exp":
				if seenExp {
					return PermError, ""
				}
				explanation = m.value
				seenExp = true
			case "redirect":
				if seenRedirect {
					return PermError, ""
				}
				redirect = m.value
				seenRedirect = true
			}
		}
	}

	for _, term := range terms {
		switch t := term.(type) {
		case directive:
			d := t
			var r Result = internalNoMatch
			switch d.mechanism {
			case "a":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom := d.domain(domain)
				r = c.check(ip, dom, d.cidr(), d.qualifier)

			case "mx":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom := d.domain(domain)
				r = c.checkMX(ip, dom, d.cidr(), d.qualifier)

			case "include":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom := d.domain(domain)
				res, _ := c.checkHost(ip, dom, sender)
				switch res {
				case Pass:
					r = Pass
				case Fail, Softfail, Neutral:
					r = internalNoMatch
				case TempError:
					return TempError, ""
				case PermError, None:
					return PermError, ""
				}
				if r == Pass {
					r = evalQualifier(d.qualifier)
				}

			case "ptr":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom := d.domain(domain)
				r = c.checkPTR(ip, dom, d.qualifier)

			case "ip4":
				if ip.To4() != nil {
					r = checkIP(ip, d.param, d.qualifier)
				}

			case "ip6":
				if ip.To4() == nil {
					r = checkIP(ip, d.param, d.qualifier)
				}

			case "all":
				res := evalQualifier(d.qualifier)
				if res == Fail {
					return res, c.processExplanation(explanation, ip, domain, sender)
				}
				return res, ""

			case "exists":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom, res := c.macro(d.param, ip, domain, sender, c.helo)
				if res == PermError {
					return PermError, ""
				}
				ips, err := c.resolver.LookupA(c.ctx, dom)
				if err != nil {
					// RFC 7208 §5.7: DNS error on exists → TempError
					return TempError, ""
				}
				if len(ips) == 0 {
					// RFC 7208 §4.6.4: count void lookups (empty response)
					c.voidCnt++
					if c.voidCnt > maxVoidLookups {
						return PermError, ""
					}
				} else {
					r = evalQualifier(d.qualifier)
				}
			}

			if r == TempError {
				return TempError, ""
			}
			if r == PermError {
				return PermError, ""
			}
			if r != internalNoMatch {
				if r == Fail {
					return r, c.processExplanation(explanation, ip, domain, sender)
				}
				return r, ""
			}

		case modifier:
			// Modifiers are already collected in the pre-scan above; skip here.
		}
	}

	if seenRedirect {
		if c.cnt >= maxDNSMechanisms {
			return PermError, ""
		}
		c.cnt++
		// RFC 7208 §6.1: the result of the redirect modifier is the result of
		// the SPF check for the target domain.
		res, _ := c.checkHost(ip, redirect, sender)
		// RFC 7208 §6.2: if the result is Fail, process exp= from this policy.
		if res == Fail {
			return res, c.processExplanation(explanation, ip, domain, sender)
		}
		return res, ""
	}

	return Neutral, ""
}

func (c *check) processExplanation(exp string, ip net.IP, domain, sender string) string {
	if exp == "" {
		return ""
	}
	// Expand exp macro
	target, res := c.macro(exp, ip, domain, sender, c.helo)
	if res != None {
		return ""
	}

	// Lookup TXT record
	txts, err := c.resolver.LookupTXT(c.ctx, target)
	if err != nil || len(txts) == 0 {
		return ""
	}

	// RFC 7208 §6.2: if there are multiple TXT records, any one may be used.
	explanation := txts[0]

	// Expand explanation macro
	expanded, res := c.macro(explanation, ip, domain, sender, c.helo)
	if res != None {
		return ""
	}
	return expanded
}

func (c *check) check(ip net.IP, domain, cidr, qualifier string) Result {
	var ips []net.IP
	var err error

	if ip.To4() == nil {
		ips, err = c.resolver.LookupAAAA(c.ctx, domain)
	} else {
		ips, err = c.resolver.LookupA(c.ctx, domain)
	}

	if err != nil {
		return TempError
	}

	for _, a := range ips {
		if r := checkIP(ip, a.String()+cidr, qualifier); r != internalNoMatch {
			return r
		}
	}
	return internalNoMatch
}

func checkIP(ip net.IP, ipstr, qualifier string) Result {
	_, ips, err := net.ParseCIDR(ipstr)
	if err == nil {
		if ips.Contains(ip) {
			return evalQualifier(qualifier)
		}
	} else {
		ipaddr := net.ParseIP(ipstr)
		if ip.Equal(ipaddr) {
			return evalQualifier(qualifier)
		}
	}
	return internalNoMatch
}

// evalQualifier returns Pass if qualifier is + or "" or other spf results accordingly
func evalQualifier(q string) Result {
	switch q {
	case "~":
		return Softfail
	case "-":
		return Fail
	case "?":
		return Neutral
	default:
		return Pass
	}
}

// checkMX checks the MX records of domain for IP match.
// RFC 7208 §4.6.4: limit to maxMXPTRRecords MX names to prevent amplification.
func (c *check) checkMX(ip net.IP, domain, cidr, qualifier string) Result {
	mxs, err := c.resolver.LookupMX(c.ctx, domain)
	if err != nil {
		return TempError
	}

	// Cap the number of MX records we process (RFC 7208 §4.6.4)
	if len(mxs) > maxMXPTRRecords {
		return PermError
	}

	for _, mx := range mxs {
		r := c.check(ip, mx, cidr, qualifier)
		switch r {
		case Pass, PermError, Fail, Softfail, Neutral:
			return r
		case TempError:
			return TempError
		}
	}
	return internalNoMatch
}

// checkPTR validates the connecting IP via reverse DNS.
// RFC 7208 §5.5: for each PTR name, validate with a forward lookup (A for IPv4, AAAA for IPv6).
// RFC 7208 §4.6.4: limit to maxMXPTRRecords PTR names to prevent amplification.
func (c *check) checkPTR(ip net.IP, domain, qualifier string) Result {
	hosts, err := c.resolver.LookupPTR(c.ctx, ip)
	if err != nil {
		return TempError
	}

	// Cap the number of PTR records we process (RFC 7208 §4.6.4)
	if len(hosts) > maxMXPTRRecords {
		hosts = hosts[:maxMXPTRRecords]
	}

	var validated []string
	for _, h := range hosts {
		// RFC 7208 §5.5: validate PTR hostname with forward lookup matching IP version
		var ips []net.IP
		if ip.To4() == nil {
			ips, _ = c.resolver.LookupAAAA(c.ctx, h)
		} else {
			ips, _ = c.resolver.LookupA(c.ctx, h)
		}
		for _, fwd := range ips {
			if fwd.Equal(ip) {
				validated = append(validated, h)
				break
			}
		}
	}

	for _, dom := range validated {
		if dom == domain || strings.HasSuffix(dom, "."+domain) {
			return evalQualifier(qualifier)
		}
	}

	return internalNoMatch
}

type modifier struct {
	name  string
	value string
}

type directive struct {
	qualifier string
	mechanism string
	param     string
}

// domain returns default domain (param) or domain specified in spf record after : sign
func (d directive) domain(domain string) string {
	if d.param != "" {
		parts := strings.SplitN(d.param, "/", 2)
		return parts[0]
	}
	return domain
}

func (d directive) cidr() string {
	n := strings.Index(d.param, "/")
	if n != -1 {
		return d.param[n:]
	}
	return ""
}

// parseSPF record and return slice with directives and modifiers.
// Mechanism names are normalized to lowercase; parameter values are preserved.
func parseSPF(spf string) []interface{} {
	// Strip v=spf1 prefix case-insensitively
	if hasPrefixFold(spf, "v=spf1") {
		spf = spf[6:]
	}
	spf = strings.TrimSpace(spf)

	var terms []any
	parts := strings.FieldsSeq(spf)
	for t := range parts {
		dirMatch := mDirective.FindStringSubmatch(t)
		if len(dirMatch) > 0 {
			terms = append(terms, directive{
				qualifier: dirMatch[1],
				mechanism: strings.ToLower(dirMatch[2]),
				param:     dirMatch[3],
			})
			continue
		} else {
			modMatch := mModifier.FindStringSubmatch(t)
			if len(modMatch) > 0 {
				terms = append(terms, modifier{
					name:  strings.ToLower(modMatch[1]),
					value: modMatch[2],
				})
			}
		}
	}
	return terms
}
