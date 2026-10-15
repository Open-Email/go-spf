package spf

import (
	"context"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

type macro struct {
	ctx      context.Context
	ip       net.IP
	domain   string
	sender   string
	helo     string
	resolver Resolver
}

// macroExpr is one "%{" macro-letter transformers *delimiter "}" (RFC 7208
// §7.1).
type macroExpr struct {
	letter  byte   // lowercase
	escape  bool   // the letter was uppercase: URL-escape the result (§7.3)
	keep    int    // the DIGIT transformer: right-hand parts to keep; 0 keeps all
	reverse bool   // the "r" transformer
	delims  string // the delimiters; none splits on "."
}

// macro expands a domain-spec (RFC 7208 §7.1).
func (c check) macro(m string, ip net.IP, domain, sender, helo string) (string, Result) {
	return c.expand(m, ip, domain, sender, helo, false)
}

// explanationText expands the TXT an exp= modifier names (RFC 7208 §6.2).
func (c check) explanationText(m string, ip net.IP, domain, sender, helo string) (string, Result) {
	return c.expand(m, ip, domain, sender, helo, true)
}

// expand answers PermError for a macro-string that is not well formed. In an
// explanation the caller then proceeds as if there were no exp= (§6.2).
func (c check) expand(m string, ip net.IP, domain, sender, helo string, explain bool) (string, Result) {
	mac := macro{
		ctx:      c.ctx,
		ip:       ip,
		domain:   domain,
		sender:   sender,
		helo:     helo,
		resolver: c.resolver,
	}
	expanded, ok := scanMacroString(m, explain, mac.eval)
	if !ok {
		return m, PermError
	}
	return expanded, None
}

// validDomainSpec checks macro-string domain-end (RFC 7208 section 7.1)
// without expansion or DNS lookups. A domain-end is a final macro expansion,
// or a dot and a toplabel, optionally followed by a root dot.
func validDomainSpec(spec string) bool {
	_, ok, endsInMacro := scanMacroStringEnd(spec, false, func(macroExpr) string { return "" })
	if !ok || spec == "" {
		return false
	}
	if endsInMacro {
		return true
	}
	spec = strings.TrimSuffix(spec, ".")
	dot := strings.LastIndexByte(spec, '.')
	if dot < 0 {
		return false
	}
	label := spec[dot+1:]
	if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	hasLetterOrHyphen := false
	for i := 0; i < len(label); i++ {
		c := lowerASCII(label[i])
		switch {
		case 'a' <= c && c <= 'z', c == '-':
			hasLetterOrHyphen = true
		case '0' <= c && c <= '9':
		default:
			return false
		}
	}
	return hasLetterOrHyphen
}

// recordName is spec with each macro standing for one valid label, which is
// what the record's own text spells once the sender's data is taken out. It
// is only asked about a spec that expanded, so one that is well formed.
func recordName(spec string) string {
	name, _ := scanMacroString(spec, false, func(macroExpr) string { return "x" })
	return name
}

// scanMacroString walks a macro-string (RFC 7208 §7.1) in one pass, copying
// the literal text, turning "%%", "%_" and "%-" into "%", " " and "%20", and
// writing what expand makes of each "%{...}". Text that follows "%%" is
// literal, so "%%{d}" is the four characters "%{d}". It reports false for a
// syntax error: a '%' followed by anything else or by nothing, a "%{" with
// no "}", or an expression parseMacroExpr refuses.
func scanMacroString(m string, explain bool, expand func(macroExpr) string) (string, bool) {
	expanded, ok, _ := scanMacroStringEnd(m, explain, expand)
	return expanded, ok
}

// scanMacroStringEnd also reports whether the final token is macro-expand,
// including %% / %_ / %-. Escaped percents followed by literal text cannot
// accidentally satisfy domain-end (for example, %%{d}).
func scanMacroStringEnd(m string, explain bool, expand func(macroExpr) string) (string, bool, bool) {
	var b strings.Builder
	endsInMacro := false
	for i := 0; i < len(m); i++ {
		if m[i] != '%' {
			if (m[i] < '!' || m[i] > '~') && !(explain && m[i] == ' ') {
				return "", false, false
			}
			b.WriteByte(m[i])
			endsInMacro = false
			continue
		}
		endsInMacro = true
		i++
		if i == len(m) {
			return "", false, false
		}
		switch m[i] {
		case '%':
			b.WriteByte('%')
		case '_':
			b.WriteByte(' ')
		case '-':
			b.WriteString("%20")
		case '{':
			end := strings.IndexByte(m[i:], '}')
			if end < 0 {
				return "", false, false
			}
			e, ok := parseMacroExpr(m[i+1:i+end], explain)
			if !ok {
				return "", false, false
			}
			b.WriteString(expand(e))
			i += end
		default:
			return "", false, false
		}
	}
	return b.String(), true, endsInMacro
}

// parseMacroExpr parses what stands between "%{" and "}": a macro-letter
// (slodipvh, and c, r and t in explanation text only, RFC 7208 §7.2), in
// either case; transformers = *DIGIT ["r"], the DIGIT nonzero (§7.3) and
// "r" in either case (ABNF strings are case-insensitive, RFC 5234 §2.3);
// then *delimiter. Anything else is a syntax error.
func parseMacroExpr(s string, explain bool) (macroExpr, bool) {
	if s == "" {
		return macroExpr{}, false
	}
	e := macroExpr{letter: lowerASCII(s[0]), escape: 'A' <= s[0] && s[0] <= 'Z'}
	switch e.letter {
	case 's', 'l', 'o', 'd', 'i', 'p', 'v', 'h':
	case 'c', 'r', 't':
		if !explain {
			return e, false
		}
	default:
		return e, false
	}
	i := 1
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}
	if i > 1 {
		digits := strings.TrimLeft(s[1:i], "0")
		if digits == "" {
			return e, false
		}
		// A value past what an int holds asks for more parts than any
		// name has: "all the available parts are used" (§7.3).
		n, err := strconv.Atoi(digits)
		if err != nil {
			n = math.MaxInt
		}
		e.keep = n
	}
	if i < len(s) && (s[i] == 'r' || s[i] == 'R') {
		e.reverse = true
		i++
	}
	e.delims = s[i:]
	for j := 0; j < len(e.delims); j++ {
		if strings.IndexByte(".-+,/_=", e.delims[j]) < 0 {
			return e, false
		}
	}
	return e, true
}

func (m *macro) eval(e macroExpr) string {
	var t string
	switch e.letter {
	case 's':
		t = m.sender
	case 'l':
		t, _ = senderParts(m.sender)
	case 'o':
		_, t = senderParts(m.sender)
	case 'd':
		t = m.domain
	case 'i':
		t = dotFormat(m.ip)
	case 'p':
		t = m.getValidatedDomain()
	case 'v':
		if m.ip.To4() != nil {
			t = "in-addr"
		} else {
			t = "ip6"
		}
	case 'h':
		t = m.helo
	case 'c':
		// RFC 7208 §7.3: the client address "for humans to read": the
		// dotted quad, or the RFC 5952 colon form for IPv6.
		t = m.ip.String()
	case 'r':
		// RFC 7208 §7.3: the receiving host's name, which go-spf is not
		// given, so the "unknown" the RFC substitutes then.
		t = "unknown"
	case 't':
		t = strconv.FormatInt(time.Now().Unix(), 10)
	}

	if t == "" {
		return ""
	}

	// RFC 7208 §7.3: split on the delimiters ("." when none are given),
	// with "no special treatment ... to leading, trailing, or consecutive
	// delimiters", so parts may be empty; reverse; keep the right-hand
	// DIGIT parts; rejoin with ".".
	delims := e.delims
	if delims == "" {
		delims = "."
	}
	parts := splitAny(t, delims)
	if e.reverse {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}
	if e.keep > 0 && e.keep < len(parts) {
		parts = parts[len(parts)-e.keep:]
	}

	result := strings.Join(parts, ".")
	if e.escape {
		// RFC 7208 §7.3: "Uppercase macros expand exactly as their
		// lowercase equivalents, and are then URL escaped."
		result = urlEscape(result)
	}
	return result
}

// splitAny splits s at every byte that is one of seps (ASCII), keeping the
// empty parts.
func splitAny(s, seps string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(seps, s[i]) >= 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// dotFormat is %{i} (RFC 7208 §7.3): the dotted quad for IPv4 and, for
// IPv6, the 32 hex nibbles separated by dots, most significant first, so
// that %{ir} gives the ip6.arpa order.
func dotFormat(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 63)
	for _, octet := range v6 {
		if len(b) > 0 {
			b = append(b, '.')
		}
		b = append(b, hex[octet>>4], '.', hex[octet&0xf])
	}
	return string(b)
}

// urlEscape keeps RFC 3986's unreserved characters (ALPHA / DIGIT / "-" /
// "." / "_" / "~") and percent-encodes every other octet, with uppercase hex
// digits (RFC 3986 §2.1).
func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// getValidatedDomain is %{p} (RFC 7208 §7.3): of the PTR names of the
// client that validate (§5.5), <domain> itself, else a subdomain of it, else
// the first; "unknown" when none does.
func (m *macro) getValidatedDomain() string {
	ptr, err := m.resolver.LookupPTR(m.ctx, m.ip)
	if err != nil || len(ptr) == 0 {
		return "unknown"
	}

	// Cap the number of PTR records we process (RFC 7208 §4.6.4)
	if len(ptr) > maxMXPTRRecords {
		ptr = ptr[:maxMXPTRRecords]
	}

	var validated []string
	for _, name := range ptr {
		// Verify PTR record with forward lookup matching IP version
		var ips []net.IP
		var err error
		if m.ip.To4() != nil {
			ips, err = m.resolver.LookupA(m.ctx, name)
		} else {
			ips, err = m.resolver.LookupAAAA(m.ctx, name)
		}
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(m.ip) {
				validated = append(validated, name)
				break
			}
		}
	}
	if len(validated) == 0 {
		return "unknown"
	}

	domain := comparableName(m.domain)
	for _, name := range validated {
		if comparableName(name) == domain {
			return name
		}
	}
	for _, name := range validated {
		if strings.HasSuffix(comparableName(name), "."+domain) {
			return name
		}
	}
	return validated[0]
}

// comparableName is name in the form two names compare equal in: lowercase,
// without the trailing dot.
func comparableName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// senderParts splits the sender into the local part (%{l}) and domain (%{o}).
// The domain follows the LAST '@': a quoted local part may hold one
// (RFC 5321 §4.1.2), a domain never does.
func senderParts(s string) (string, string) {
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}
