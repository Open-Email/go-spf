package spf_test

import (
	"net"
	"strings"
	"testing"

	"github.com/Open-Email/go-spf"
)

// TestTermGrammar: RFC 7208 §4.6.1 and §12. A term is a directive,
// [qualifier] mechanism, where the mechanism is one of the eight names, whole,
// followed by what that mechanism allows (a and mx: [":" domain-spec]
// [dual-cidr-length]); or a modifier, name "=" ..., where the '=' comes
// before any ':' or '/' and the name is ALPHA *(ALPHA / DIGIT / "-" / "_" /
// "."). Anything else is a syntax error, and "if there are any syntax errors
// anywhere in the record, check_host() returns immediately with the result
// "permerror"" (§4.6). Unknown modifiers are ignored (Open-Email/smtp-in#136).
func TestTermGrammar(t *testing.T) {
	const (
		v4 = "192.0.2.10"   // in example.com's /24 (192.0.2.1, MX host 192.0.2.2)
		v6 = "2001:db8::99" // in example.com's /64 (2001:db8::1, MX host 2001:db8::2)
	)
	zone := func(record string) *mockResolver {
		return resolverFull(
			map[string][]string{"example.com": {record}},
			map[string][]string{
				"example.com":          {"mx.example.com"},
				"mail.out.example.com": {"mx.example.com"},
			},
			map[string][]string{
				"example.com":          {"192.0.2.1"},
				"mx.example.com":       {"192.0.2.2"},
				"mail.out.example.com": {"192.0.2.1"},
			},
			map[string][]string{
				"example.com":    {"2001:db8::1"},
				"mx.example.com": {"2001:db8::2"},
			},
			nil,
		)
	}
	var cases []testCase
	add := func(record, sender string, want4, want6 spf.Result) {
		for _, c := range []struct {
			ip   string
			want spf.Result
		}{{v4, want4}, {v6, want6}} {
			cases = append(cases, testCase{
				name: c.ip + " " + record, ip: c.ip, domain: "example.com", sender: sender, want: c.want, r: zone(record),
			})
		}
	}
	const u = "user@example.com"

	// a and mx with a dual-cidr-length and no domain-spec use the current
	// domain (§5.3, §5.4); the ip4 length applies to an IPv4 client, the ip6
	// length to an IPv6 one, each defaulting to the full address.
	add("v=spf1 a/24 -all", u, spf.Pass, spf.Fail)
	add("v=spf1 mx/24 -all", u, spf.Pass, spf.Fail)
	add("v=spf1 a//64 -all", u, spf.Fail, spf.Pass)
	add("v=spf1 mx//64 -all", u, spf.Fail, spf.Pass)
	add("v=spf1 a/24//64 -all", u, spf.Pass, spf.Pass)
	add("v=spf1 mx/24//64 -all", u, spf.Pass, spf.Pass)
	add("v=spf1 A/24 -all", u, spf.Pass, spf.Fail)
	add("v=spf1 a:example.com/24//64 -all", u, spf.Pass, spf.Pass)
	add("v=spf1 a -all", u, spf.Fail, spf.Fail)

	// The dual-cidr-length is what follows the domain-spec, so a '/' that
	// is a macro delimiter stays in the domain-spec.
	add("v=spf1 a:%{l/}.example.com/24 -all", "mail/out@example.com", spf.Pass, spf.Fail)
	add("v=spf1 mx:%{l/}.example.com/24 -all", "mail/out@example.com", spf.Pass, spf.Fail)

	// Lengths out of range, with a leading zero, or not in that shape.
	add("v=spf1 a/33 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 a//129 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 a/024 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 mx/24/64 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 a/ -all", u, spf.PermError, spf.PermError)

	// A ':' brings a domain-spec, which cannot be empty; mechanisms
	// without a dual-cidr-length take none.
	add("v=spf1 a: -all", u, spf.PermError, spf.PermError)
	add("v=spf1 mx:/24 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ptr/0 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 include:example.net/24 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 include -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4:"+v4+" ip6:"+v6+" include: -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4:"+v4+" ip6:"+v6+" exists: -all", u, spf.PermError, spf.PermError)
	add("v=spf1 all:example.com", u, spf.PermError, spf.PermError)
	add("v=spf1 -all/8", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4/24 -all", u, spf.PermError, spf.PermError)

	// A mechanism name matches the whole name, not a prefix of the term.
	add("v=spf1 abc -all", u, spf.PermError, spf.PermError)
	add("v=spf1 allfoo", u, spf.PermError, spf.PermError)
	add("v=spf1 mxfoo -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4"+v4+" -all", u, spf.PermError, spf.PermError)
	add("v=spf1 includeexample.net -all", u, spf.PermError, spf.PermError)
	add("v=spf1 -all.", u, spf.PermError, spf.PermError)

	// An unknown mechanism is a syntax error, also after a match.
	add("v=spf1 foo:bar -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4:"+v4+" ip6:"+v6+" moo -all", u, spf.PermError, spf.PermError)
	add("v=spf1 -foo/24 -all", u, spf.PermError, spf.PermError)
	add("v=spf1 ip4:"+v4+" redirect:example.net", u, spf.PermError, spf.PermError)

	// An unknown modifier is ignored; '=' before any ':' or '/' makes a
	// modifier, and its name must be well formed.
	add("v=spf1 a=b ip4:"+v4+" ip6:"+v6+" -all", u, spf.Pass, spf.Pass)
	add("v=spf1 moo.cow-far_out=man:dog/cat ip4:"+v4+" ip6:"+v6+" -all", u, spf.Pass, spf.Pass)
	add("v=spf1 include=example.net ip4:"+v4+" ip6:"+v6+" -all", u, spf.Pass, spf.Pass)
	add("v=spf1 moo.cow/far_out=man:dog/cat ip4:"+v4+" ip6:"+v6+" -all", u, spf.PermError, spf.PermError)
	add("v=spf1 1up=foo ip4:"+v4+" ip6:"+v6+" -all", u, spf.PermError, spf.PermError)
	add("v=spf1 =all", u, spf.PermError, spf.PermError)
	add("v=spf1 -x=y ip4:"+v4+" ip6:"+v6+" -all", u, spf.PermError, spf.PermError)
	add("v=spf1 foo+bar=x ip4:"+v4+" ip6:"+v6+" -all", u, spf.PermError, spf.PermError)
	// An '=' after the first ':' is part of a directive: here a macro
	// delimiter.
	add("v=spf1 exists:%{l=}.example.com -all", "mail=out@example.com", spf.Pass, spf.Pass)

	runCases(t, cases)
}

// suiteZone is the zone data of one openspf scenario.
type suiteZone struct {
	txt, mx, a, aaaa, ptr map[string][]string
}

type suiteCase struct {
	name, helo, host, mailfrom string
	want                       spf.Result
}

// runSuite runs openspf cases against their scenario's zone. The identity
// is MAIL FROM, or HELO when MAIL FROM is empty.
func runSuite(t *testing.T, z suiteZone, cases []suiteCase) {
	t.Helper()
	r := resolverFull(z.txt, z.mx, z.a, z.aaaa, z.ptr)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			domain := tc.helo
			if at := strings.LastIndex(tc.mailfrom, "@"); at >= 0 {
				domain = tc.mailfrom[at+1:]
			}
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP(tc.host), domain, tc.mailfrom, tc.helo, r); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestOpenSPFTermSyntax runs the term-syntax cases of the openspf RFC 7208
// test suite (rfc7208-tests.yml, as pyspf ships it), each scenario against
// its own zone data. Left out, with the reason:
//   - a-numeric, a-numeric-toplabel, a-only-toplabel(-trailing-dot),
//     mx-numeric-top-label, invalid-domain: go-spf does not check that a
//     domain-spec ends in a valid toplabel (§7.1);
//   - a-colon-domain(-ip4mapped), mx-colon-domain(-ip4mapped): the name
//     holds ':' and '/', which IDNA's Lookup profile refuses (go-spf#4);
//   - ptr-cname-loop, exists-dnserr: the mock resolver has no CNAME or
//     timeout;
//   - the ip4/ip6 network and length cases other than a bare ip4/ip6.
func TestOpenSPFTermSyntax(t *testing.T) {
	const mail = "mail.example.com"

	t.Run("Record evaluation", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"t1.example.com": {"v=spf1 ip4:1.2.3.4 -all moo"},
				"t2.example.com": {"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"},
				"t3.example.com": {"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"},
				"t4.example.com": {"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"},
				"t5.example.com": {"v=spf1 redirect=t5.example.com ~all"},
				"t6.example.com": {"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"},
				"t7.example.com": {"v=spf1 ip4:1.2.3.4"},
				"t8.example.com": {"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"},
			},
			a: map[string][]string{mail: {"1.2.3.4"}},
		}, []suiteCase{
			{"detect-errors-anywhere", mail, "1.2.3.4", "foo@t1.example.com", spf.PermError},
			{"modifier-charset-good", mail, "1.2.3.4", "foo@t2.example.com", spf.Pass},
			{"modifier-charset-bad1", mail, "1.2.3.4", "foo@t3.example.com", spf.PermError},
			{"modifier-charset-bad2", mail, "1.2.3.4", "foo@t4.example.com", spf.PermError},
			{"redirect-after-mechanisms1", mail, "1.2.3.4", "foo@t5.example.com", spf.Softfail},
			{"redirect-after-mechanisms2", mail, "1.2.3.5", "foo@t6.example.com", spf.Fail},
			{"default-result", mail, "1.2.3.5", "foo@t7.example.com", spf.Neutral},
			{"redirect-is-modifier", mail, "1.2.3.4", "foo@t8.example.com", spf.PermError},
		})
	})

	t.Run("ALL mechanism syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"e1.example.com": {"v=spf1 -all."},
				"e2.example.com": {"v=spf1 -all:foobar"},
				"e3.example.com": {"v=spf1 -all/8"},
				"e4.example.com": {"v=spf1 ?all"},
				"e5.example.com": {"v=spf1 all -all"},
			},
			a: map[string][]string{mail: {"1.2.3.4"}},
		}, []suiteCase{
			{"all-dot", mail, "1.2.3.4", "foo@e1.example.com", spf.PermError},
			{"all-arg", mail, "1.2.3.4", "foo@e2.example.com", spf.PermError},
			{"all-cidr", mail, "1.2.3.4", "foo@e3.example.com", spf.PermError},
			{"all-neutral", mail, "1.2.3.4", "foo@e4.example.com", spf.Neutral},
			{"all-double", mail, "1.2.3.4", "foo@e5.example.com", spf.Pass},
		})
	})

	t.Run("PTR mechanism syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"e1.example.com": {"v=spf1 ptr/0 -all"},
				"e2.example.com": {"v=spf1 ptr:example.com -all"},
				"e3.example.com": {"v=spf1 ptr -all"},
				"e4.example.com": {"v=spf1 ptr -all"},
				"e5.example.com": {"v=spf1 ptr:"},
				"e6.example.com": {"v=spf1 ptr:example.Com -all"},
			},
			a: map[string][]string{
				mail:             {"1.2.3.4"},
				"e3.example.com": {"1.2.3.4"},
			},
			aaaa: map[string][]string{
				mail:             {"2001:db8::1"},
				"e3.example.com": {"cafe:babe::1"},
			},
			ptr: map[string][]string{
				"1.2.3.4":      {"e3.example.com", "e4.example.com", mail},
				"cafe:babe::1": {"e3.example.com"},
				"2001:db8::1":  {"mail.Example.com"},
			},
		}, []suiteCase{
			{"ptr-cidr", mail, "1.2.3.4", "foo@e1.example.com", spf.PermError},
			{"ptr-match-target", mail, "1.2.3.4", "foo@e2.example.com", spf.Pass},
			{"ptr-match-implicit", mail, "1.2.3.4", "foo@e3.example.com", spf.Pass},
			{"ptr-nomatch-invalid", mail, "1.2.3.4", "foo@e4.example.com", spf.Fail},
			{"ptr-match-ip6", mail, "CAFE:BABE::1", "foo@e3.example.com", spf.Pass},
			{"ptr-empty-domain", mail, "1.2.3.4", "foo@e5.example.com", spf.PermError},
			{"ptr-case-change", mail, "2001:db8::1", "bar@e6.example.com", spf.Pass},
		})
	})

	t.Run("A mechanism syntax", func(t *testing.T) {
		dual := []string{"1.2.3.5"}
		dual6 := []string{"2001:db8:1234::dead:beef"}
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"e1.example.com":   {"v=spf1 a/0 -all"},
				"e2.example.com":   {"v=spf1 a/0 -all"},
				"e2a.example.com":  {"v=spf1 a//0 -all"},
				"e2b.example.com":  {"v=spf1 a//0 -all"},
				"ipv6.example.com": {"v=spf1 a -all"},
				"e3.example.com":   {"v=spf1 a:foo.example.com\x00"},
				"e6.example.com":   {"v=spf1 a//33 -all"},
				"e6a.example.com":  {"v=spf1 a/33 -all"},
				"e7.example.com":   {"v=spf1 a//129 -all"},
				"e8.example.com":   {"v=spf1 a/24//64 -all"},
				"e8e.example.com":  {"v=spf1 a/24/64 -all"},
				"e8a.example.com":  {"v=spf1 a/24 -all"},
				"e8b.example.com":  {"v=spf1 a//64 -all"},
				"e9.example.com":   {"v=spf1 a:example.com:8080"},
				"e10.example.com":  {"v=spf1 a:foo.example.com/24"},
				"e12.example.com":  {"v=spf1 a:example.-com"},
				"e13.example.com":  {"v=spf1 a:"},
				"e14.example.com":  {"v=spf1 a:foo.example.xn--zckzah -all"},
			},
			a: map[string][]string{
				mail:                     {"1.2.3.4"},
				"e2.example.com":         {"1.1.1.1"},
				"e2b.example.com":        {"1.1.1.1"},
				"ipv6.example.com":       {"1.1.1.1"},
				"e8.example.com":         dual,
				"e8e.example.com":        dual,
				"e8a.example.com":        dual,
				"e8b.example.com":        dual,
				"foo.example.com":        {"1.1.1.1", "1.2.3.5"},
				"foo.example.xn--zckzah": {"1.2.3.4"},
			},
			aaaa: map[string][]string{
				"e2.example.com":   {"1234::2"},
				"e2a.example.com":  {"1234::1"},
				"ipv6.example.com": {"1234::1"},
				"e8.example.com":   dual6,
				"e8e.example.com":  dual6,
				"e8a.example.com":  dual6,
				"e8b.example.com":  dual6,
			},
		}, []suiteCase{
			{"a-cidr6", mail, "1.2.3.4", "foo@e6.example.com", spf.Fail},
			{"a-bad-cidr4", mail, "1.2.3.4", "foo@e6a.example.com", spf.PermError},
			{"a-bad-cidr6", mail, "1.2.3.4", "foo@e7.example.com", spf.PermError},
			{"a-dual-cidr-ip4-match", mail, "1.2.3.4", "foo@e8.example.com", spf.Pass},
			{"a-dual-cidr-ip4-err", mail, "1.2.3.4", "foo@e8e.example.com", spf.PermError},
			{"a-dual-cidr-ip6-match", mail, "2001:db8:1234::cafe:babe", "foo@e8.example.com", spf.Pass},
			{"a-dual-cidr-ip4-default", mail, "1.2.3.4", "foo@e8b.example.com", spf.Fail},
			{"a-dual-cidr-ip6-default", mail, "2001:db8:1234::cafe:babe", "foo@e8a.example.com", spf.Fail},
			{"a-multi-ip1", mail, "1.2.3.4", "foo@e10.example.com", spf.Pass},
			{"a-bad-domain", mail, "1.2.3.4", "foo@e9.example.com", spf.PermError},
			{"a-nxdomain", mail, "1.2.3.4", "foo@e1.example.com", spf.Fail},
			{"a-cidr4-0", mail, "1.2.3.4", "foo@e2.example.com", spf.Pass},
			{"a-cidr4-0-ip6", mail, "1234::1", "foo@e2.example.com", spf.Fail},
			{"a-cidr6-0-ip4", mail, "1.2.3.4", "foo@e2a.example.com", spf.Fail},
			{"a-cidr6-0-ip4mapped", mail, "::FFFF:1.2.3.4", "foo@e2a.example.com", spf.Fail},
			{"a-cidr6-0-ip6", mail, "1234::1", "foo@e2a.example.com", spf.Pass},
			{"a-ip6-dualstack", mail, "1234::1", "foo@ipv6.example.com", spf.Pass},
			{"a-cidr6-0-nxdomain", mail, "1234::1", "foo@e2b.example.com", spf.Fail},
			{"a-null", mail, "1.2.3.5", "foo@e3.example.com", spf.PermError},
			{"a-dash-in-toplabel", mail, "1.2.3.4", "foo@e14.example.com", spf.Pass},
			{"a-bad-toplabel", mail, "1.2.3.4", "foo@e12.example.com", spf.PermError},
			{"a-empty-domain", mail, "1.2.3.4", "foo@e13.example.com", spf.PermError},
		})
	})

	t.Run("Include mechanism semantics and syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"ip5.example.com": {"v=spf1 ip4:1.2.3.5 -all"},
				"e6.example.com":  {"v=spf1 include +all"},
				"e8.example.com":  {"v=spf1 include: -all"},
				"e9.example.com":  {"v=spf1 include:ip5.example.com/24 -all"},
			},
			a: map[string][]string{mail: {"1.2.3.4"}},
		}, []suiteCase{
			{"include-syntax-error", mail, "1.2.3.4", "foo@e6.example.com", spf.PermError},
			{"include-cidr", mail, "1.2.3.4", "foo@e9.example.com", spf.PermError},
			{"include-empty-domain", mail, "1.2.3.4", "foo@e8.example.com", spf.PermError},
		})
	})

	t.Run("MX mechanism syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				mail:              {"v=spf1 mx"},
				"e1.example.com":  {"v=spf1 mx/0 -all"},
				"e2.example.com":  {"v=spf1 mx/0 -all"},
				"e2a.example.com": {"v=spf1 mx//0 -all"},
				"e2b.example.com": {"v=spf1 mx//0 -all"},
				"e3.example.com":  {"v=spf1 mx:foo.example.com\x00"},
				"e4.example.com":  {"v=spf1 mx"},
				"e6.example.com":  {"v=spf1 mx//33 -all"},
				"e6a.example.com": {"v=spf1 mx/33 -all"},
				"e7.example.com":  {"v=spf1 mx//129 -all"},
				"e9.example.com":  {"v=spf1 mx:example.com:8080"},
				"e10.example.com": {"v=spf1 mx:foo.example.com/24"},
				"e12.example.com": {"v=spf1 mx:example.-com"},
				"e13.example.com": {"v=spf1 mx: -all"},
			},
			mx: map[string][]string{
				mail:              {""},
				"e1.example.com":  {"e1.example.com"},
				"e2.example.com":  {"e2.example.com"},
				"e2a.example.com": {"e2a.example.com"},
				"e2b.example.com": {"e2b.example.com"},
				"foo.example.com": {"foo1.example.com"},
			},
			a: map[string][]string{
				mail:               {"1.2.3.4"},
				"e2.example.com":   {"1.1.1.1"},
				"e2b.example.com":  {"1.1.1.1"},
				"e4.example.com":   {"1.2.3.4"},
				"foo1.example.com": {"1.1.1.1", "1.2.3.5"},
			},
			aaaa: map[string][]string{
				"e2.example.com":  {"1234::2"},
				"e2a.example.com": {"1234::1"},
			},
		}, []suiteCase{
			{"mx-cidr6", mail, "1.2.3.4", "foo@e6.example.com", spf.Fail},
			{"mx-bad-cidr4", mail, "1.2.3.4", "foo@e6a.example.com", spf.PermError},
			{"mx-bad-cidr6", mail, "1.2.3.4", "foo@e7.example.com", spf.PermError},
			{"mx-multi-ip1", mail, "1.2.3.4", "foo@e10.example.com", spf.Pass},
			{"mx-bad-domain", mail, "1.2.3.4", "foo@e9.example.com", spf.PermError},
			{"mx-nxdomain", mail, "1.2.3.4", "foo@e1.example.com", spf.Fail},
			{"mx-cidr4-0", mail, "1.2.3.4", "foo@e2.example.com", spf.Pass},
			{"mx-cidr4-0-ip6", mail, "1234::1", "foo@e2.example.com", spf.Fail},
			{"mx-cidr6-0-ip4", mail, "1.2.3.4", "foo@e2a.example.com", spf.Fail},
			{"mx-cidr6-0-ip4mapped", mail, "::FFFF:1.2.3.4", "foo@e2a.example.com", spf.Fail},
			{"mx-cidr6-0-ip6", mail, "1234::1", "foo@e2a.example.com", spf.Pass},
			{"mx-cidr6-0-nxdomain", mail, "1234::1", "foo@e2b.example.com", spf.Fail},
			{"mx-null", mail, "1.2.3.5", "foo@e3.example.com", spf.PermError},
			{"mx-bad-toplab", mail, "1.2.3.4", "foo@e12.example.com", spf.PermError},
			{"mx-empty", mail, "1.2.3.4", "", spf.Neutral},
			{"mx-implicit", mail, "1.2.3.4", "foo@e4.example.com", spf.Neutral},
			{"mx-empty-domain", mail, "1.2.3.4", "foo@e13.example.com", spf.PermError},
		})
	})

	t.Run("EXISTS mechanism syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"e1.example.com": {"v=spf1 exists:"},
				"e2.example.com": {"v=spf1 exists"},
				"e3.example.com": {"v=spf1 exists:mail.example.com/24"},
				"e4.example.com": {"v=spf1 exists:mail.example.com"},
				"e5.example.com": {"v=spf1 exists:mail6.example.com -all"},
			},
			a:    map[string][]string{mail: {"1.2.3.4"}},
			aaaa: map[string][]string{"mail6.example.com": {"cafe:babe::4"}},
		}, []suiteCase{
			{"exists-empty-domain", mail, "1.2.3.4", "foo@e1.example.com", spf.PermError},
			{"exists-implicit", mail, "1.2.3.4", "foo@e2.example.com", spf.PermError},
			{"exists-cidr", mail, "1.2.3.4", "foo@e3.example.com", spf.PermError},
			{"exists-ip4", mail, "1.2.3.4", "foo@e4.example.com", spf.Pass},
			{"exists-ip6", mail, "CAFE:BABE::3", "foo@e4.example.com", spf.Pass},
			{"exists-ip6only", mail, "CAFE:BABE::3", "foo@e5.example.com", spf.Fail},
		})
	})

	t.Run("IP4 and IP6 mechanism syntax", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"ip4.example.com": {"v=spf1 ip4"},
				"ip6.example.com": {"v=spf1 -all ip6"},
			},
			a: map[string][]string{mail: {"1.2.3.4"}},
		}, []suiteCase{
			{"bare-ip4", mail, "1.2.3.4", "foo@ip4.example.com", spf.PermError},
			{"bare-ip6", mail, "1.2.3.4", "foo@ip6.example.com", spf.PermError},
		})
	})

	t.Run("Semantics of exp and other modifiers", func(t *testing.T) {
		runSuite(t, suiteZone{
			txt: map[string][]string{
				"e5.example.com":  {"v=spf1 1up=foo"},
				"e6.example.com":  {"v=spf1 =all"},
				"e19.example.com": {"v=spf1 default=pass"},
				"e20.example.com": {"v=spf1 default=+"},
			},
			a: map[string][]string{mail: {"1.2.3.4"}},
		}, []suiteCase{
			{"invalid-modifier", mail, "1.2.3.4", "foo@e5.example.com", spf.PermError},
			{"empty-modifier-name", mail, "1.2.3.4", "foo@e6.example.com", spf.PermError},
			{"default-modifier-obsolete", mail, "1.2.3.4", "foo@e19.example.com", spf.Neutral},
			{"default-modifier-obsolete2", mail, "1.2.3.4", "foo@e20.example.com", spf.Neutral},
		})
	})
}
