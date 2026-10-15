package spf_test

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-spf"
)

// RFC 7208 §7.4: "The <sender> is strong-bad@email.example.com. The IPv4
// SMTP client IP is 192.0.2.3. The IPv6 SMTP client IP is 2001:db8::cb01.
// The PTR domain name of the client IP is mx.example.org."
const (
	rfcSender = "strong-bad@email.example.com"
	rfcDomain = "email.example.com"
	rfcIPv4   = "192.0.2.3"
	rfcIPv6   = "2001:db8::cb01"
	rfcPTR    = "mx.example.org"
)

// For an IPv6 client %{i} is "a dot-format address" (RFC 7208 §7.3): the 32
// nibbles, most significant first, so that %{ir} is the order §7.4's IPv6
// row spells.
const (
	rfcIPv6Nibbles         = "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
	rfcIPv6NibblesReversed = "1.0.b.c.0.0.0.0." + "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
)

type macroRow struct{ macro, want string }

// macroExpr is one %{...} of a macro-string.
var macroExpr = regexp.MustCompile(`%{[^}]+}`)

// rfcMacroRows are RFC 7208 §7.4's examples (both tables, the IPv6 row
// included), each macro-string with its rows for the client address given,
// plus %{p} for the PTR name §7.4 names. The rows with %{i} for the IPv6
// client other than §7.4's own are the same strings with the nibbles in.
func rfcMacroRows(ip string) []macroRow {
	rows := []macroRow{
		{"%{s}", "strong-bad@email.example.com"},
		{"%{o}", "email.example.com"},
		{"%{d}", "email.example.com"},
		{"%{d4}", "email.example.com"},
		{"%{d3}", "email.example.com"},
		{"%{d2}", "example.com"},
		{"%{d1}", "com"},
		{"%{dr}", "com.example.email"},
		{"%{d2r}", "example.email"},
		{"%{l}", "strong-bad"},
		{"%{l-}", "strong.bad"},
		{"%{lr}", "strong-bad"},
		{"%{lr-}", "bad.strong"},
		{"%{l1r-}", "strong"},
		{"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		{"%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"},
		{"%{p}", rfcPTR},
	}
	if ip == rfcIPv4 {
		return append(rows,
			macroRow{"%{i}", "192.0.2.3"},
			macroRow{"%{ir}", "3.2.0.192"},
			macroRow{"%{v}", "in-addr"},
			macroRow{"%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"},
			macroRow{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
			macroRow{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
		)
	}
	return append(rows,
		macroRow{"%{i}", rfcIPv6Nibbles},
		macroRow{"%{ir}", rfcIPv6NibblesReversed},
		macroRow{"%{v}", "ip6"},
		macroRow{"%{ir}.%{v}._spf.%{d2}", rfcIPv6NibblesReversed + ".ip6._spf.example.com"},
		macroRow{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp." + rfcIPv6NibblesReversed + ".ip6._spf.example.com"},
		macroRow{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", rfcIPv6NibblesReversed + ".ip6.strong.lp._spf.example.com"},
	)
}

// rfcPTRResolver answers %{p} for both §7.4 client addresses with the
// validated name mx.example.org (RFC 7208 §5.5: PTR, then a forward lookup).
func rfcPTRResolver() *mockResolver {
	return resolverFull(nil, nil,
		map[string][]string{rfcPTR: {rfcIPv4}},
		map[string][]string{rfcPTR: {rfcIPv6}},
		map[string][]string{rfcIPv4: {rfcPTR}, rfcIPv6: {rfcPTR}},
	)
}

// TestMacroRFC7208Examples expands every RFC 7208 §7.4 example for the IPv4
// and the IPv6 client. The letters allowed only in explanation text (c, r,
// t, RFC 7208 §7.2) are a syntax error in a domain-spec (Open-Email/smtp-in#134).
func TestMacroRFC7208Examples(t *testing.T) {
	orig := spf.DefaultResolver
	defer func() { spf.DefaultResolver = orig }()
	spf.DefaultResolver = rfcPTRResolver()

	for _, client := range []string{rfcIPv4, rfcIPv6} {
		ip := net.ParseIP(client)
		for _, row := range rfcMacroRows(client) {
			if got := spf.Macro(row.macro, ip, rfcDomain, rfcSender, "hello.server"); got != row.want {
				t.Errorf("client %s: Macro(%q) = %q, want %q", client, row.macro, got, row.want)
			}
		}
		for _, letter := range []string{"%{c}", "%{r}", "%{t}"} {
			if _, res := spf.MacroResult(letter, ip, rfcDomain, rfcSender, "hello.server"); res != spf.PermError {
				t.Errorf("client %s: %s in a domain-spec: got %s, want %s", client, letter, res, spf.PermError)
			}
		}
	}
}

// TestMacroUppercaseRFC7208Examples: "Uppercase macros expand exactly as
// their lowercase equivalents, and are then URL escaped" (RFC 7208 §7.3).
// Every §7.4 example in uppercase, for both clients, gives the lowercase
// expansion with each octet outside RFC 3986's unreserved set
// (ALPHA / DIGIT / "-" / "." / "_" / "~") percent-encoded. The transformer
// "r" is case-insensitive like every ABNF string (RFC 5234 §2.3).
func TestMacroUppercaseRFC7208Examples(t *testing.T) {
	orig := spf.DefaultResolver
	defer func() { spf.DefaultResolver = orig }()
	spf.DefaultResolver = rfcPTRResolver()

	for _, client := range []string{rfcIPv4, rfcIPv6} {
		ip := net.ParseIP(client)
		for _, row := range rfcMacroRows(client) {
			upper := macroExpr.ReplaceAllStringFunc(row.macro, strings.ToUpper)
			// The only octet outside the unreserved set in any §7.4
			// expansion is the '@' of %{s}.
			want := strings.ReplaceAll(row.want, "@", "%40")
			if got := spf.Macro(upper, ip, rfcDomain, rfcSender, "hello.server"); got != want {
				t.Errorf("client %s: Macro(%q) = %q, want %q", client, upper, got, want)
			}
		}
		if got := spf.Macro("%{H}", ip, rfcDomain, rfcSender, "hello.server"); got != "hello.server" {
			t.Errorf("client %s: Macro(%%{H}) = %q, want %q", client, got, "hello.server")
		}
		for _, letter := range []string{"%{C}", "%{R}", "%{T}"} {
			if _, res := spf.MacroResult(letter, ip, rfcDomain, rfcSender, "hello.server"); res != spf.PermError {
				t.Errorf("client %s: %s in a domain-spec: got %s, want %s", client, letter, res, spf.PermError)
			}
		}
	}
}

// TestMacroUppercaseURLEscape: the escaping comes after the transformers
// (split, reverse, keep, rejoin with "."), works on octets (UTF-8 here) and
// uses uppercase hex digits (RFC 3986 §2.1). A lowercase macro is never
// escaped.
func TestMacroUppercaseURLEscape(t *testing.T) {
	ip := net.ParseIP(rfcIPv4)
	for _, tc := range []struct{ sender, macro, want string }{
		{"~jack&jill=up-a_b3.c@e8.example.com", "%{L}", "~jack%26jill%3Dup-a_b3.c"},
		{"~jack&jill=up-a_b3.c@e8.example.com", "%{l}", "~jack&jill=up-a_b3.c"},
		{"jack&jill=up@example.com", "%{S}", "jack%26jill%3Dup%40example.com"},
		{"user+tag@example.com", "%{L}", "user%2Btag"},
		{"user+tag@example.com", "%{L+}", "user.tag"},
		{"a+b-c@example.com", "%{L-}", "a%2Bb.c"},
		{"a+b-c@example.com", "%{LR-}", "c.a%2Bb"},
		{`"a b"@example.com`, "%{L}", "%22a%20b%22"},
		{"jörg@example.com", "%{L}", "j%C3%B6rg"},
		{"a/b@example.com", "%{L}", "a%2Fb"},
	} {
		if got := spf.Macro(tc.macro, ip, "example.com", tc.sender, "hello.server"); got != tc.want {
			t.Errorf("Macro(%q) with sender %q = %q, want %q", tc.macro, tc.sender, got, tc.want)
		}
	}
}

// TestExistsClientAddressIPv6: a record that looks the client address up,
// RFC 7208 §7.4's exists:%{ir}.%{v}._spf.%{d} or the forward
// exists:%{i}._spf... shape (Salesforce publishes one), matches an IPv6
// client through its dot-format nibbles, as it matches an IPv4 client.
func TestExistsClientAddressIPv6(t *testing.T) {
	a := map[string][]string{
		"3.2.0.192.in-addr._spf.example.com":             {"127.0.0.2"},
		rfcIPv6NibblesReversed + ".ip6._spf.example.com": {"127.0.0.2"},
		"192.0.2.3._spf.mta.example.com":                 {"127.0.0.2"},
		rfcIPv6Nibbles + "._spf.mta.example.com":         {"127.0.0.2"},
	}
	var cases []testCase
	for _, record := range []string{
		"v=spf1 exists:%{ir}.%{v}._spf.%{d} -all",
		"v=spf1 exists:%{i}._spf.mta.%{d} -all",
	} {
		for _, tc := range []struct {
			ip   string
			want spf.Result
		}{
			{rfcIPv4, spf.Pass},
			{rfcIPv6, spf.Pass},
			// Another address in the same /64 has no record.
			{"2001:db8::cb02", spf.Fail},
		} {
			cases = append(cases, testCase{
				name: tc.ip + " " + record, ip: tc.ip, domain: "example.com", sender: rfcSender, want: tc.want,
				r: resolverFull(map[string][]string{"example.com": {record}}, nil, a, nil, nil),
			})
		}
	}
	runCases(t, cases)
}

// TestTrackingExists runs RFC 7208 Appendix C's tracking record through
// check_host(): the name it looks up embeds the HELO name, both halves of the
// sender and the client address, which for an IPv6 client is the nibbles.
func TestTrackingExists(t *testing.T) {
	const record = "v=spf1 exists:_h.%{h}._l.%{l}._o.%{o}._i.%{i}._spf.%{d} ?all"
	for _, tc := range []struct{ ip, i string }{
		{rfcIPv4, "192.0.2.3"},
		{rfcIPv6, rfcIPv6Nibbles},
	} {
		name := "_h.mx.example.org._l.strong-bad._o.email.example.com._i." + tc.i + "._spf.email.example.com"
		r := resolverFull(
			map[string][]string{rfcDomain: {record}},
			nil,
			map[string][]string{name: {"127.0.0.2"}},
			nil, nil,
		)
		if got := spf.CheckHostWithResolver(ctx, net.ParseIP(tc.ip), rfcDomain, rfcSender, "mx.example.org", r); got != spf.Pass {
			t.Errorf("client %s: got %s, want %s (looked up %s)", tc.ip, got, spf.Pass, name)
		}
	}
}

// TestUppercaseMacroInMechanism: an uppercase macro in a mechanism's
// domain-spec expands (then URL-escapes, a no-op for a host name) instead of
// standing for nothing. Before, "a:%{H}" was an empty name and a PermError.
func TestUppercaseMacroInMechanism(t *testing.T) {
	const helo = "msgbas2x.cos.example.com"
	for _, record := range []string{
		"v=spf1 a:%{H} -all",
		"v=spf1 exists:%{L}.%{O} -all",
		"v=spf1 exists:%{IR}.%{V}._spf.%{D2} -all",
	} {
		for _, client := range []string{"192.0.2.3", rfcIPv6} {
			r := resolverFull(
				map[string][]string{"email.example.com": {record}},
				nil,
				map[string][]string{
					"strong-bad.email.example.com":                   {"127.0.0.2"},
					"3.2.0.192.in-addr._spf.example.com":             {"127.0.0.2"},
					rfcIPv6NibblesReversed + ".ip6._spf.example.com": {"127.0.0.2"},
					helo: {"192.0.2.3"},
				},
				map[string][]string{helo: {rfcIPv6}},
				nil,
			)
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP(client), rfcDomain, rfcSender, helo, r); got != spf.Pass {
				t.Errorf("client %s, %s: got %s, want %s", client, record, got, spf.Pass)
			}
		}
	}
}

// TestExplanationMacros: the explanation text an exp= modifier fetches
// (RFC 7208 §6.2) also allows c, r and t (§7.2). %{c} is the client address
// "for humans to read" (§7.3): the dotted quad, or IPv6's colon form, never
// %{i}'s nibbles. %{r} is the receiving host, which go-spf is not told:
// "unknown" (§7.3). Uppercase letters are URL-escaped there too.
func TestExplanationMacros(t *testing.T) {
	for _, tc := range []struct{ name, ip, sender, text, want string }{
		{"c ipv4", rfcIPv4, rfcSender, "Connections from %{c} not authorized.", "Connections from 192.0.2.3 not authorized."},
		{"c and ir ipv6", rfcIPv6, rfcSender, "%{c} is queried as %{ir}.%{v}.arpa", "2001:db8::cb01 is queried as " + rfcIPv6NibblesReversed + ".ip6.arpa"},
		{"C ipv6", rfcIPv6, rfcSender, "client=%{C}", "client=2001%3Adb8%3A%3Acb01"},
		{"C ipv4", rfcIPv4, rfcSender, "client=%{C}", "client=192.0.2.3"},
		{"r", rfcIPv4, rfcSender, "checked by %{r}", "checked by unknown"},
		{"R", rfcIPv4, rfcSender, "checked by %{R}", "checked by unknown"},
		{"L", rfcIPv4, "~jack&jill=up-a_b3.c@example.com", "http://example.com/why.html?l=%{L}", "http://example.com/why.html?l=~jack%26jill%3Dup-a_b3.c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := resolverWith(map[string][]string{
				"example.com":         {"v=spf1 -all exp=explain.%{d}"},
				"explain.example.com": {tc.text},
			})
			res, exp := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP(tc.ip), "example.com", tc.sender, "", r)
			if res != spf.Fail {
				t.Fatalf("got %s, want %s", res, spf.Fail)
			}
			if exp != tc.want {
				t.Errorf("explanation: got %q, want %q", exp, tc.want)
			}
		})
	}

	t.Run("t", func(t *testing.T) {
		r := resolverWith(map[string][]string{
			"example.com":         {"v=spf1 -all exp=explain.%{d}"},
			"explain.example.com": {"at %{t} and %{T}"},
		})
		before := time.Now().Unix()
		_, exp := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP(rfcIPv4), "example.com", rfcSender, "", r)
		after := time.Now().Unix()
		var stamps []int64
		for _, f := range strings.Fields(exp) {
			if n, err := strconv.ParseInt(f, 10, 64); err == nil {
				stamps = append(stamps, n)
			}
		}
		if len(stamps) != 2 {
			t.Fatalf("explanation %q: want two timestamps", exp)
		}
		for _, n := range stamps {
			if n < before || n > after {
				t.Errorf("explanation %q: timestamp %d outside [%d, %d]", exp, n, before, after)
			}
		}
	})

	// RFC 7208 §7.2: the same letters in a domain-spec are a syntax error.
	t.Run("not in a domain-spec", func(t *testing.T) {
		for _, client := range []string{rfcIPv4, rfcIPv6} {
			for _, record := range []string{
				"v=spf1 exists:%{c}._spf.example.com -all",
				"v=spf1 exists:%{C}._spf.example.com -all",
				"v=spf1 exists:%{r}._spf.example.com -all",
				"v=spf1 exists:%{t}._spf.example.com -all",
			} {
				r := resolverFull(
					map[string][]string{"example.com": {record}},
					nil,
					map[string][]string{
						"192.0.2.3._spf.example.com": {"127.0.0.2"},
						"unknown._spf.example.com":   {"127.0.0.2"},
					},
					nil, nil,
				)
				if got := spf.CheckHostWithResolver(ctx, net.ParseIP(client), "example.com", rfcSender, "", r); got != spf.PermError {
					t.Errorf("client %s, %s: got %s, want %s", client, record, got, spf.PermError)
				}
			}
		}
	})
}

// TestLongExpandedNameTruncated: "When the result of macro expansion is used
// in a domain name query, if the expanded domain name exceeds 253
// characters ..., the left side is truncated to fit, by removing successive
// domain labels (and their following dots) until the total length does not
// exceed 253 characters" (RFC 7208 §7.3). The name is looked up, not refused.
func TestLongExpandedNameTruncated(t *testing.T) {
	const client = "192.0.2.3"
	// 190 octets: 63 + 1 + 63 + 1 + 50 + 1 + 11.
	suffix := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 50) + ".example.com"
	const long = "somewhat.long.exp.example.com" // 29 octets
	for _, tc := range []struct {
		name, sender, record, queried string
	}{
		{
			name:    "253 octets kept whole",
			sender:  strings.Repeat("a", 62) + "@example.com",
			record:  "v=spf1 exists:%{l}." + suffix + " -all",
			queried: strings.Repeat("a", 62) + "." + suffix,
		},
		{
			name:    "253 octets and a trailing dot kept whole",
			sender:  strings.Repeat("a", 62) + "@example.com",
			record:  "v=spf1 exists:%{l}." + suffix + ". -all",
			queried: strings.Repeat("a", 62) + "." + suffix,
		},
		{
			name:    "254 octets lose the leftmost label",
			sender:  strings.Repeat("a", 63) + "@example.com",
			record:  "v=spf1 exists:%{l}." + suffix + " -all",
			queried: suffix,
		},
		{
			// 9 x 30 + 16 = 286 octets: somewhat, long, exp, example,
			// com and somewhat go (39 octets), one label at a time, not
			// one macro's expansion at a time.
			name:    "labels go one at a time until it fits",
			sender:  "test@" + long,
			record:  "v=spf1 exists:" + strings.Repeat("%{o}.", 9) + "_spf.example.com -all",
			queried: "long.exp.example.com." + strings.Repeat(long+".", 7) + "_spf.example.com",
		},
		{
			// The label no query could carry is not part of the query.
			name:    "a removed label may be one no query could carry",
			sender:  strings.Repeat("a", 64) + "@example.com",
			record:  "v=spf1 exists:%{l}." + suffix + " -all",
			queried: suffix,
		},
		{
			name:    "a: target",
			sender:  strings.Repeat("a", 63) + "@example.com",
			record:  "v=spf1 a:%{l}." + suffix + " -all",
			queried: suffix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.queried) > 253 {
				t.Fatalf("fixture: queried name is %d octets", len(tc.queried))
			}
			r := resolverFull(
				map[string][]string{"example.com": {tc.record}},
				nil,
				map[string][]string{tc.queried: {"127.0.0.2", client}},
				nil, nil,
			)
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP(client), "example.com", tc.sender, "", r); got != spf.Pass {
				t.Errorf("got %s, want %s (expected lookup of %s)", got, spf.Pass, tc.queried)
			}
		})
	}

	t.Run("redirect target", func(t *testing.T) {
		r := resolverWith(map[string][]string{
			"example.com": {"v=spf1 redirect=%{l}." + suffix},
			suffix:        {"v=spf1 ip4:" + client + " -all"},
		})
		if got := spf.CheckHostWithResolver(ctx, net.ParseIP(client), "example.com", strings.Repeat("a", 63)+"@example.com", "", r); got != spf.Pass {
			t.Errorf("got %s, want %s", got, spf.Pass)
		}
	})

	// The exp= target: 7 + 8 x 30 + 11 = 258 octets, and "foobar." goes.
	t.Run("exp target", func(t *testing.T) {
		r := resolverWith(map[string][]string{
			long: {"v=spf1 -all exp=foobar." + strings.Repeat("%{o}.", 8) + "example.com"},
			strings.Repeat(long+".", 8) + "example.com": {"Congratulations!  That was tricky."},
		})
		res, exp := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP(client), long, "test@"+long, "", r)
		if res != spf.Fail {
			t.Fatalf("got %s, want %s", res, spf.Fail)
		}
		if want := "Congratulations!  That was tricky."; exp != want {
			t.Errorf("explanation: got %q, want %q", exp, want)
		}
	})
}

// TestUppercaseMacroUnqueryable: an escaped expansion that no query can carry
// ("user%2Btag") names nothing, as its lowercase twin does
// (Open-Email/smtp-in#129): the mechanism does not match, and the record is
// not a PermError.
func TestUppercaseMacroUnqueryable(t *testing.T) {
	var cases []testCase
	for _, tc := range []struct{ sender, record string }{
		{"user+tag@example.com", "v=spf1 exists:%{L}._spf.example.com -all"},
		{rfcSender, "v=spf1 exists:%{S}._spf.example.com -all"},
	} {
		cases = append(cases, testCase{
			name: tc.sender + " " + tc.record, ip: rfcIPv4, domain: "example.com", sender: tc.sender, want: spf.Fail,
			r: resolverWith(map[string][]string{"example.com": {tc.record}}),
		})
	}
	runCases(t, cases)
}
