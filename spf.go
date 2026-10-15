// RFC 7208

package spf

import (
	"context"
	"net"
	"net/netip"
	"strconv"
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
	} else if strings.LastIndexByte(sender, '@') == 0 {
		// RFC 7208 section 4.3: an absent local part is postmaster.
		// The local part is everything before the LAST '@'; a decoded
		// quoted local part can itself start with or contain '@'.
		sender = "postmaster" + sender
	}

	c := check{
		ctx:      ctx,
		cnt:      0,
		resolver: idnaResolver{r},
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
	// RFC 7208 §4.3: a malformed <domain> makes check_host() return None.
	// An include/redirect target the record spells wrong never reaches here
	// (validDomainSpec answers PermError for it). One that only the expanded data
	// made unqueryable does, and include and redirect turn its None into
	// PermError as for a target with no SPF record (RFC 7208 §5.2, §6.1).
	var err error
	domain, err = canonicalDNSName(domain)
	if err != nil || !strings.Contains(domain, ".") {
		return None, ""
	}
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

	// RFC 7208 §4.6: "If there are any syntax errors anywhere in the
	// record, check_host() returns immediately with the result
	// "permerror", without further interpretation." That includes a term
	// that is neither a directive nor a modifier (an unknown mechanism,
	// §4.6.1), and the macros of every domain-spec (§7.1): of a term
	// evaluation would not reach, and of exp=, which is only read on a Fail.
	for _, term := range terms {
		if _, ok := term.(invalidTerm); ok {
			return PermError, ""
		}
		if spec, ok := domainSpecOf(term); ok && !validDomainSpec(spec) {
			return PermError, ""
		}
		if m, ok := term.(modifier); ok {
			if _, valid := scanMacroString(m.value, false, func(macroExpr) string { return "" }); !valid {
				return PermError, ""
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
				dom, result := c.domainSpec(d.domain(domain), ip, domain, sender)
				if result != None {
					return result, ""
				}
				r = c.check(ip, dom, d.cidr4, d.cidr6, d.qualifier)

			case "mx":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom, result := c.domainSpec(d.domain(domain), ip, domain, sender)
				if result != None {
					return result, ""
				}
				r = c.checkMX(ip, dom, d.cidr4, d.cidr6, d.qualifier)

			case "include":
				if c.cnt >= maxDNSMechanisms {
					return PermError, ""
				}
				c.cnt++
				dom, result := c.domainSpec(d.domain(domain), ip, domain, sender)
				if result != None {
					return result, ""
				}
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
				dom, result := c.domainSpec(d.domain(domain), ip, domain, sender)
				if result != None {
					return result, ""
				}
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
				dom, res := c.domainSpec(d.domainSpec, ip, domain, sender)
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
		target, result := c.domainSpec(redirect, ip, domain, sender)
		if result != None {
			return result, ""
		}
		res, targetExplanation := c.checkHost(ip, target, sender)
		// RFC 7208 §6.1: if no SPF record is found, the result is PermError rather than None.
		if res == None {
			return PermError, ""
		}
		// RFC 7208 section 6.2: redirect uses the target policy's exp,
		// never the original policy's explanation.
		return res, targetExplanation
	}

	return Neutral, ""
}

func (c *check) processExplanation(exp string, ip net.IP, domain, sender string) string {
	if exp == "" {
		return ""
	}
	// Expand exp macro
	target, res := c.domainSpec(exp, ip, domain, sender)
	if res != None {
		return ""
	}

	// Lookup TXT record
	txts, err := c.resolver.LookupTXT(c.ctx, target)
	if err != nil || len(txts) != 1 {
		return ""
	}

	// RFC 7208 section 6.2: exactly one explanation TXT record is required.
	explanation := txts[0]

	// Expand explanation macro
	expanded, res := c.explanationText(explanation, ip, domain, sender, c.helo)
	if res != None {
		return ""
	}
	return expanded
}

// check matches ip against the addresses of domain: A records and the ip4
// prefix length for an IPv4 client, AAAA records and the ip6 one for IPv6.
func (c *check) check(ip net.IP, domain string, cidr4, cidr6 int, qualifier string) Result {
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

	if len(ips) == 0 {
		// RFC 7208 §4.6.4: count void lookups (empty response)
		c.voidCnt++
		if c.voidCnt > maxVoidLookups {
			return PermError
		}
		return internalNoMatch
	}

	for _, a := range ips {
		if prefixMatch(ip, a, cidr4, cidr6) {
			return evalQualifier(qualifier)
		}
	}
	return internalNoMatch
}

// prefixMatch reports whether ip and addr agree in their first cidr4 bits
// (IPv4 client) or cidr6 bits (IPv6 client).
func prefixMatch(ip, addr net.IP, cidr4, cidr6 int) bool {
	if v4 := ip.To4(); v4 != nil {
		a4 := addr.To4()
		if a4 == nil {
			return false
		}
		mask := net.CIDRMask(cidr4, 32)
		return v4.Mask(mask).Equal(a4.Mask(mask))
	}
	a16 := addr.To16()
	if a16 == nil {
		return false
	}
	mask := net.CIDRMask(cidr6, 128)
	return ip.To16().Mask(mask).Equal(a16.Mask(mask))
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
func (c *check) checkMX(ip net.IP, domain string, cidr4, cidr6 int, qualifier string) Result {
	mxs, err := c.resolver.LookupMX(c.ctx, domain)
	if err != nil {
		return TempError
	}

	if len(mxs) == 0 {
		// RFC 7208 §4.6.4: count void lookups (empty response)
		c.voidCnt++
		if c.voidCnt > maxVoidLookups {
			return PermError
		}
		return internalNoMatch
	}

	// Cap the number of MX records we process (RFC 7208 §4.6.4)
	if len(mxs) > maxMXPTRRecords {
		return PermError
	}

	for _, mx := range mxs {
		r := c.check(ip, mx, cidr4, cidr6, qualifier)
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
		// RFC 7208 §5.5: if a DNS error occurs during the PTR lookup, the mechanism fails to match.
		return internalNoMatch
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
	// param is the ip4 or ip6 network, as written.
	param string
	// domainSpec is the target of a, mx, ptr, include or exists; "" when
	// the term names none (a, mx and ptr then use the current domain).
	domainSpec string
	// cidr4 and cidr6 are the dual-cidr-length of a and mx: 32 and 128
	// when not given.
	cidr4, cidr6 int
}

// invalidTerm is a term that is neither a directive nor a modifier: a
// syntax error, which makes the whole record a PermError (RFC 7208 §4.6).
type invalidTerm struct {
	text string
}

// domain returns the domain-spec of the term, or the current domain when it
// names none.
func (d directive) domain(current string) string {
	if d.domainSpec != "" {
		return d.domainSpec
	}
	return current
}

// domainSpecOf returns the domain-spec a term carries: the target of a:,
// mx:, ptr:, include: and exists:, and the value of redirect= and exp=.
func domainSpecOf(term interface{}) (string, bool) {
	switch t := term.(type) {
	case directive:
		switch t.mechanism {
		case "a", "mx", "ptr", "include", "exists":
			return t.domainSpec, t.domainSpec != ""
		}
	case modifier:
		if t.name == "redirect" || t.name == "exp" {
			return t.value, true
		}
	}
	return "", false
}

// parseSPF splits a record into its terms (RFC 7208 §4.6.1): directives,
// modifiers, and an invalidTerm for each term that is neither.
// Mechanism and modifier names are normalized to lowercase; parameter
// values are preserved.
func parseSPF(spf string) []interface{} {
	// Published SPF records are printable ASCII, with SP as the only
	// term separator (RFC 7208 sections 3.1 and 4.6.1; RFC 8616 section 4).
	// Validate before splitting so controls cannot create separate terms.
	for i := 0; i < len(spf); i++ {
		if spf[i] < ' ' || spf[i] > '~' {
			return []interface{}{invalidTerm{spf}}
		}
	}
	// Strip v=spf1 prefix case-insensitively
	if hasPrefixFold(spf, "v=spf1") {
		spf = spf[6:]
	}

	var terms []any
	for t := range strings.FieldsSeq(spf) {
		terms = append(terms, parseTerm(t))
	}
	return terms
}

// parseTerm parses one term. "Modifiers always contain an equals ('=')
// character immediately after the name, and before any ":" or "/"
// characters that might be part of the macro-string" (§4.6.1); anything
// else is a directive, whose mechanism name is all of the text up to the
// first ':' or '/', and must be one of the eight of §5.
func parseTerm(t string) interface{} {
	if i := strings.IndexAny(t, ":/="); i >= 0 && t[i] == '=' {
		if !validModifierName(t[:i]) {
			return invalidTerm{t}
		}
		return modifier{name: strings.ToLower(t[:i]), value: t[i+1:]}
	}

	d := directive{cidr4: 32, cidr6: 128}
	rest := t
	if rest != "" && strings.IndexByte("+-?~", rest[0]) >= 0 {
		d.qualifier, rest = rest[:1], rest[1:]
	}
	end := strings.IndexAny(rest, ":/")
	if end < 0 {
		end = len(rest)
	}
	d.mechanism, rest = strings.ToLower(rest[:end]), rest[end:]

	var ok bool
	switch d.mechanism {
	case "all":
		ok = rest == ""
	case "include", "exists":
		// "include" ":" domain-spec, "exists" ":" domain-spec
		d.domainSpec, ok = strings.CutPrefix(rest, ":")
		ok = ok && d.domainSpec != ""
	case "ptr":
		// "ptr" [ ":" domain-spec ]
		ok = rest == ""
		if !ok {
			d.domainSpec, ok = strings.CutPrefix(rest, ":")
			ok = ok && d.domainSpec != ""
		}
	case "a", "mx":
		// "a" [ ":" domain-spec ] [ dual-cidr-length ]
		d.domainSpec, d.cidr4, d.cidr6, ok = splitDualCIDR(rest)
	case "ip4", "ip6":
		// "ip4" ":" ip4-network [ ip4-cidr-length ], the same for ip6
		d.param, ok = strings.CutPrefix(rest, ":")
		ok = ok && validIPNetwork(d.param, d.mechanism == "ip6")
	}
	if !ok {
		return invalidTerm{t}
	}
	return d
}

// splitDualCIDR parses what follows "a" or "mx": [ ":" domain-spec ]
// [ dual-cidr-length ], dual-cidr-length = [ ip4-cidr-length ]
// [ "/" ip6-cidr-length ] (§5.3, §5.4, §12). The lengths are the "//N" and
// "/N" at the very end, after the domain-spec, so a '/' inside it (a macro
// delimiter, say) stays in the domain-spec.
func splitDualCIDR(s string) (spec string, cidr4, cidr6 int, ok bool) {
	cidr4, cidr6 = 32, 128
	if i := strings.LastIndex(s, "//"); i >= 0 && allDigits(s[i+2:]) {
		if cidr6, ok = cidrLength(s[i+2:], 128); !ok {
			return "", 0, 0, false
		}
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 && allDigits(s[i+1:]) {
		if cidr4, ok = cidrLength(s[i+1:], 32); !ok {
			return "", 0, 0, false
		}
		s = s[:i]
	}
	if s == "" {
		return "", cidr4, cidr6, true
	}
	spec, ok = strings.CutPrefix(s, ":")
	if !ok || spec == "" {
		return "", 0, 0, false
	}
	return spec, cidr4, cidr6, true
}

// cidrLength parses a prefix length: "0", or a number without a leading
// zero, at most max (§12: ip4-cidr-length 0-32, ip6-cidr-length 0-128).
func cidrLength(s string, max int) (int, bool) {
	if !allDigits(s) || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > max {
		return 0, false
	}
	return n, true
}

// validIPNetwork validates even mechanisms for the other client family and
// those after an earlier match, so malformed networks are syntax errors.
func validIPNetwork(network string, ipv6 bool) bool {
	parts := strings.Split(network, "/")
	if len(parts) > 2 {
		return false
	}
	ip, err := netip.ParseAddr(parts[0])
	if err != nil || ip.Zone() != "" || ip.Is6() != ipv6 {
		return false
	}
	if len(parts) == 2 {
		max := 32
		if ipv6 {
			max = 128
		}
		_, ok := cidrLength(parts[1], max)
		return ok
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// validModifierName: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
// (§4.6.1).
func validModifierName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		alpha := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !('0' <= c && c <= '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return name != ""
}
