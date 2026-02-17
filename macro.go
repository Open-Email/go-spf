package spf

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
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
}

func (c check) macro(m string, ip net.IP, domain, sender, helo string) (string, Result) {
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
	}

	return macroMatch.ReplaceAllStringFunc(m, mac.eval), None
}

func (m *macro) eval(s string) string {
	// s is something like "%{s}" or "%{l1r-}"
	// strip %{ and }
	inner := s[2 : len(s)-1]

	if len(inner) == 0 {
		return ""
	}

	// 1. Macro letter
	letter := inner[0]
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
		t = m.ip.String()
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
	default:
		// RFC 7208 §7.2: unknown macro letters expand to empty string.
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
		} else if char == 'r' {
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
	return strings.Join(parts, ".")
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

func senderParts(s string) (string, string) {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) < 2 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}
