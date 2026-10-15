package spf

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	macroSyntax   = regexp.MustCompile(`%[^{_\-%}]`)
	macroMatch    = regexp.MustCompile("%{[^}]+}")
	macroReplacer = strings.NewReplacer("%%", "%", "%_", " ", "%-", "%20")
)

type macro struct {
	ctx      context.Context
	ip       net.IP
	domain   string
	sender   string
	helo     string
	resolver Resolver
	// explain is set for explanation text, the only place the c, r and t
	// letters are allowed (RFC 7208 §7.2).
	explain bool
}

// macro expands a domain-spec (RFC 7208 §7.1).
func (c check) macro(m string, ip net.IP, domain, sender, helo string) (string, Result) {
	return c.expand(m, ip, domain, sender, helo, false)
}

// explanationText expands the TXT an exp= modifier names (RFC 7208 §6.2).
func (c check) explanationText(m string, ip net.IP, domain, sender, helo string) (string, Result) {
	return c.expand(m, ip, domain, sender, helo, true)
}

func (c check) expand(m string, ip net.IP, domain, sender, helo string, explain bool) (string, Result) {
	// Skip %% (literal %) for syntax check
	if len(macroSyntax.FindAllString(strings.ReplaceAll(m, "%%", ""), -1)) != 0 {
		return m, PermError
	}

	m = macroReplacer.Replace(m)

	mac := macro{
		ctx:      c.ctx,
		ip:       ip,
		domain:   domain,
		sender:   sender,
		helo:     helo,
		resolver: c.resolver,
		explain:  explain,
	}

	return macroMatch.ReplaceAllStringFunc(m, mac.eval), None
}

// recordName is spec with each macro standing for one valid label, which is
// what the record's own text spells once the sender's data is taken out. A
// letter eval does not expand in a domain-spec, in either case, stands for
// nothing, as it does in eval.
func recordName(spec string) string {
	return macroMatch.ReplaceAllStringFunc(macroReplacer.Replace(spec), func(s string) string {
		if strings.IndexByte("slodipvh", lowerASCII(s[2])) < 0 {
			return ""
		}
		return "x"
	})
}

func (m *macro) eval(s string) string {
	// s is something like "%{s}" or "%{l1r-}"
	// strip %{ and }
	inner := s[2 : len(s)-1]

	if len(inner) == 0 {
		return ""
	}

	// 1. Macro letter. RFC 7208 §7.3: "Uppercase macros expand exactly as
	// their lowercase equivalents, and are then URL escaped."
	letter := inner[0]
	escape := 'A' <= letter && letter <= 'Z'
	letter = lowerASCII(letter)
	rest := inner[1:]

	var t string
	switch letter {
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
		if !m.explain {
			return ""
		}
		// RFC 7208 §7.3: the client address "for humans to read": the
		// dotted quad, or the RFC 5952 colon form for IPv6.
		t = m.ip.String()
	case 'r':
		if !m.explain {
			return ""
		}
		// RFC 7208 §7.3: the receiving host's name, which go-spf is not
		// given, so the "unknown" the RFC substitutes then.
		t = "unknown"
	case 't':
		if !m.explain {
			return ""
		}
		t = strconv.FormatInt(time.Now().Unix(), 10)
	default:
		// A letter outside RFC 7208 §7.2 (or c, r, t in a domain-spec)
		// expands to the empty string.
		return ""
	}

	// 2. Transformers and Delimiters
	// transformers = *DIGIT [ "r" ]
	// delimiter = "." / "-" / "+" / "," / "/" / "_" / "="

	var digits string
	var reverse bool
	var delimiters string

	for _, char := range rest {
		if char >= '0' && char <= '9' {
			if delimiters != "" || reverse {
				continue
			}
			digits += string(char)
		} else if char == 'r' || char == 'R' {
			if delimiters != "" || reverse {
				continue
			}
			reverse = true
		} else if strings.ContainsRune(".-+,/_=", char) {
			delimiters += string(char)
		}
	}

	if t == "" {
		return ""
	}

	// Split by delimiters
	// RFC 7208 §7.1: if the delimiter character is not supplied, "." is used.
	if delimiters == "" {
		delimiters = "."
	}

	parts := strings.FieldsFunc(t, func(r rune) bool {
		return strings.ContainsRune(delimiters, r)
	})

	// Reverse if needed
	if reverse {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}

	// Keep last N parts
	if digits != "" {
		n, _ := strconv.Atoi(digits)
		if n > 0 && n < len(parts) {
			parts = parts[len(parts)-n:]
		}
	}

	// Join back with "."
	result := strings.Join(parts, ".")
	if escape {
		result = urlEscape(result)
	}
	return result
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

func (m *macro) getValidatedDomain() string {
	// RFC 7208 §5.5
	ptr, err := m.resolver.LookupPTR(m.ctx, m.ip)
	if err != nil || len(ptr) == 0 {
		return "unknown"
	}

	// Cap the number of PTR records we process (RFC 7208 §4.6.4)
	if len(ptr) > maxMXPTRRecords {
		ptr = ptr[:maxMXPTRRecords]
	}

	for _, domain := range ptr {
		// Verify PTR record with forward lookup matching IP version
		var ips []net.IP
		var err error
		if m.ip.To4() != nil {
			ips, err = m.resolver.LookupA(m.ctx, domain)
		} else {
			ips, err = m.resolver.LookupAAAA(m.ctx, domain)
		}

		if err != nil {
			continue
		}

		for _, ip := range ips {
			if ip.Equal(m.ip) {
				return domain
			}
		}
	}

	return "unknown"
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
