package spf_test

import (
	"net"
	"strings"
	"testing"

	"github.com/Open-Email/go-spf"
)

// TestMacroSyntaxErrors: a domain-spec must follow RFC 7208 §7.1's grammar.
// macro-expand = "%{" macro-letter transformers *delimiter "}" / "%%" / "%_"
// / "%-"; macro-letter is one of slodipvh (c, r and t only in explanation
// text, §7.2), in either case; transformers = *DIGIT ["r"], and a DIGIT
// "MUST be nonzero" (§7.3). Anything else is a syntax error: a PermError,
// not a letter that expands to nothing (Open-Email/smtp-in#134).
func TestMacroSyntaxErrors(t *testing.T) {
	ip := net.ParseIP(rfcIPv4)
	for _, m := range []string{
		// Letters outside §7.2, and the explanation-only ones.
		"%{z}", "x%{z}.example.com", "%{Z}", "%{a}.example.com", "%{x}",
		"%{c}", "%{C}", "%{r}", "%{R}", "%{t}", "%{T}", "%{c}x.example.com",
		// A zero DIGIT.
		"%{d0}", "%{d00}", "%{l0r-}", "%{D0}",
		// A '%' with nothing valid after it.
		"foo%", "%", "x.%", "%(ir).example.com", "foo%.example.com", "%a",
		// An unclosed or empty expression.
		"%{d", "%{d.example.com", "%{", "%{}", "%{}.example.com",
		// Anything between the braces that is not *DIGIT ["r"] *delimiter.
		"%{dx}", "%{d2r1}", "%{d.2}", "%{d-r}", "%{drr}", "%{d r}", "%{ d}", "%{d }", "%{d:}", "%{d%}",
	} {
		if got, res := spf.MacroResult(m, ip, rfcDomain, rfcSender, "hello.server"); res != spf.PermError {
			t.Errorf("MacroResult(%q) = %q, %s; want %s", m, got, res, spf.PermError)
		}
	}

	// Well formed, for contrast.
	for _, tc := range []struct{ m, want string }{
		{"%{d01}", "com"},
		{"%{d2}", "example.com"},
		{"%{d127}", "email.example.com"},
		{"%{d128}", "email.example.com"},
		// More parts than a name can have: "all the available parts".
		{"%{d99999999999999999999999}", "email.example.com"},
		{"%{dR}", "com.example.email"},
		{"%{d2r}", "example.email"},
		{"%{d.-+,/_=}", "email.example.com"},
		{"%{d}}", "email.example.com}"},
		{"{d}", "{d}"},
		{"%_%-%%", " %20%"},
	} {
		got, res := spf.MacroResult(tc.m, ip, rfcDomain, rfcSender, "hello.server")
		if res != spf.None || got != tc.want {
			t.Errorf("MacroResult(%q) = %q, %s; want %q, %s", tc.m, got, res, tc.want, spf.None)
		}
	}
}

// TestExplanationMacroSyntax: explanation text follows the same grammar with
// c, r and t allowed (RFC 7208 §7.2). A syntax error there is reported, and
// check_host() then gives no explanation (§6.2), see
// TestSyntaxErrorAnywhereInRecord.
func TestExplanationMacroSyntax(t *testing.T) {
	ip := net.ParseIP(rfcIPv4)
	for _, m := range []string{"%{z} denied", "%{d0}", "100%", "%{c", "%{cx}"} {
		if got, res := spf.ExplanationMacro(m, ip, rfcDomain, rfcSender, "hello.server"); res != spf.PermError {
			t.Errorf("ExplanationMacro(%q) = %q, %s; want %s", m, got, res, spf.PermError)
		}
	}
	for _, tc := range []struct{ m, want string }{
		{"%{c} denied", "192.0.2.3 denied"},
		{"%{r} denied", "unknown denied"},
		{"100%% sure: %%{d}", "100% sure: %{d}"},
	} {
		got, res := spf.ExplanationMacro(tc.m, ip, rfcDomain, rfcSender, "hello.server")
		if res != spf.None || got != tc.want {
			t.Errorf("ExplanationMacro(%q) = %q, %s; want %q, %s", tc.m, got, res, tc.want, spf.None)
		}
	}
}

// TestMacroPercentEscapes: "%%" is a literal '%' (RFC 7208 §7.1), and the
// text after it is literal too: "%%{d}" is the six characters "%{d}", not a
// '%' before an expanded %{d}.
func TestMacroPercentEscapes(t *testing.T) {
	ip := net.ParseIP(rfcIPv4)
	for _, tc := range []struct{ m, want string }{
		{"%%{d}", "%{d}"},
		{"%%{z}", "%{z}"},
		{"%%{d0}", "%{d0}"},
		{"%%%{d}", "%email.example.com"},
		{"%%%%{d}", "%%{d}"},
		{"%%%%", "%%"},
		{"%%_", "%_"},
		{"%%-", "%-"},
		{"50%%", "50%"},
	} {
		got, res := spf.MacroResult(tc.m, ip, rfcDomain, rfcSender, "hello.server")
		if res != spf.None || got != tc.want {
			t.Errorf("MacroResult(%q) = %q, %s; want %q, %s", tc.m, got, res, tc.want, spf.None)
		}
	}
}

// TestMacroEmptyParts: "no special treatment is given to leading, trailing,
// or consecutive delimiters in input strings, and so the list of parts might
// contain empty strings" (RFC 7208 §7.3). The empty parts are reversed,
// counted and rejoined like any other.
func TestMacroEmptyParts(t *testing.T) {
	ip := net.ParseIP(rfcIPv4)
	for _, tc := range []struct{ sender, m, want string }{
		{"a--b@example.com", "%{l-}", "a..b"},
		{"a..b@example.com", "%{l}", "a..b"},
		{"-a-b-@example.com", "%{l-}", ".a.b."},
		{"-a-b-@example.com", "%{lr-}", ".b.a."},
		{"a-b-@example.com", "%{l1-}", ""},
		{"a-b-@example.com", "%{l2-}", "b."},
		{"a-b-@example.com", "%{l2r-}", "b.a"},
		{"a+-b@example.com", "%{l+-}", "a..b"},
		// No delimiter in the value: one part, as before.
		{"strong-bad@email.example.com", "%{l}", "strong-bad"},
	} {
		got, res := spf.MacroResult(tc.m, ip, "example.com", tc.sender, "hello.server")
		if res != spf.None || got != tc.want {
			t.Errorf("MacroResult(%q) with sender %q = %q, %s; want %q", tc.m, tc.sender, got, res, tc.want)
		}
	}

	// Through check_host(): the name looked up keeps the empty label, so it
	// is not the name the dropped part used to make, and does not match.
	r := resolverFull(
		map[string][]string{"example.com": {"v=spf1 exists:%{l-}._spf.example.com -all"}},
		nil,
		map[string][]string{"a.b._spf.example.com": {"127.0.0.2"}},
		nil, nil,
	)
	if got := spf.CheckHostWithResolver(ctx, ip, "example.com", "a--b@example.com", "", r); got != spf.Fail {
		t.Errorf("exists:%%{l-}._spf.example.com for a--b: got %s, want %s", got, spf.Fail)
	}
}

// TestMacroPPrefersDomain: "If the <domain> is present in the list of
// validated domains, it SHOULD be used. Otherwise, if a subdomain of the
// <domain> is present, it SHOULD be used. Otherwise, any name from the list
// can be used" (RFC 7208 §7.3). Only validated names count (§5.5).
func TestMacroPPrefersDomain(t *testing.T) {
	orig := spf.DefaultResolver
	defer func() { spf.DefaultResolver = orig }()

	const client = "192.0.2.3"
	ip := net.ParseIP(client)
	for _, tc := range []struct {
		name      string
		ptr       []string
		validated []string
		want      string
	}{
		{"domain itself", []string{"mx.other.example", "example.com"}, []string{"mx.other.example", "example.com"}, "example.com"},
		{"a subdomain", []string{"mx.other.example", "mx.example.com"}, []string{"mx.other.example", "mx.example.com"}, "mx.example.com"},
		{"domain before a subdomain", []string{"mx.example.com", "example.com"}, []string{"mx.example.com", "example.com"}, "example.com"},
		{"a suffix that is not a subdomain", []string{"x.example.net", "badexample.com"}, []string{"x.example.net", "badexample.com"}, "x.example.net"},
		{"an unvalidated subdomain", []string{"mx.example.com", "x.example.net"}, []string{"x.example.net"}, "x.example.net"},
		{"none validated", []string{"mx.example.com"}, nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := map[string][]string{}
			for _, name := range tc.ptr {
				a[name] = []string{"198.51.100.1"}
			}
			for _, name := range tc.validated {
				a[name] = []string{client}
			}
			spf.DefaultResolver = resolverFull(nil, nil, a, nil, map[string][]string{client: tc.ptr})
			if got := spf.Macro("%{p}", ip, "example.com", "u@example.com", ""); got != tc.want {
				t.Errorf("%%{p} = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSyntaxErrorAnywhereInRecord: "If there are any syntax errors anywhere
// in the record, check_host() returns immediately with the result
// "permerror", without further interpretation" (RFC 7208 §4.6). That holds for
// a malformed macro in a term evaluation would not reach (the client matched
// earlier) and in exp=, which is only read on a Fail. A syntax error in the
// explanation TEXT is different: the check proceeds "as if no "exp"
// modifier was given" (§6.2).
func TestSyntaxErrorAnywhereInRecord(t *testing.T) {
	const client = "192.0.2.3"
	a := map[string][]string{"user.example.com": {"127.0.0.2"}}
	var cases []testCase
	for _, tc := range []struct {
		record string
		want   spf.Result
	}{
		{"v=spf1 ip4:" + client + " exists:%{z}.example.com -all", spf.PermError},
		{"v=spf1 ip4:" + client + " a:%{d0}.example.com -all", spf.PermError},
		{"v=spf1 ip4:" + client + " mx:%{d -all", spf.PermError},
		{"v=spf1 ip4:" + client + " include:foo% -all", spf.PermError},
		{"v=spf1 ip4:" + client + " ptr:%{c}.example.com -all", spf.PermError},
		{"v=spf1 ip4:" + client + " redirect=%{x}.example.com", spf.PermError},
		{"v=spf1 +all exp=%{r}.example.com", spf.PermError},
		{"v=spf1 -all exp=%{t}.example.com", spf.PermError},
		// Well formed: evaluation is unchanged.
		{"v=spf1 ip4:" + client + " exists:%{l}.example.com -all", spf.Pass},
		{"v=spf1 exists:%{l}.example.com -all", spf.Pass},
		{"v=spf1 -all exp=%{l}.example.com", spf.Fail},
		{"v=spf1 ip4:" + client + " exists:%%{l}.example.com -all", spf.Pass},
	} {
		cases = append(cases, testCase{
			name: tc.record, ip: client, domain: "example.com", sender: "user@example.com", want: tc.want,
			r: resolverFull(map[string][]string{"example.com": {tc.record}}, nil, a, nil, nil),
		})
	}
	runCases(t, cases)

	t.Run("syntax error in the explanation text", func(t *testing.T) {
		r := resolverWith(map[string][]string{
			"example.com":         {"v=spf1 -all exp=explain.example.com"},
			"explain.example.com": {"%{z} may not send"},
		})
		res, exp := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP(client), "example.com", "user@example.com", "", r)
		if res != spf.Fail || exp != "" {
			t.Errorf("got %s, %q; want %s and no explanation", res, exp, spf.Fail)
		}
	})
}

// TestOpenSPFMacroScenario runs the "Macro expansion rules" scenario of the
// openspf RFC 7208 test suite (rfc7208-tests.yml, as pyspf ships it) against
// its own zone data. Where the suite accepts two results, the comment says
// which one go-spf gives and why.
func TestOpenSPFMacroScenario(t *testing.T) {
	long := "somewhat.long.exp.example.com"
	r := resolverFull(
		map[string][]string{
			"example.com.d.spf.example.com": {"v=spf1 redirect=a.spf.example.com"},
			"a.spf.example.com":             {"v=spf1 include:o.spf.example.com. ~all"},
			"o.spf.example.com":             {"v=spf1 ip4:192.168.218.40"},
			"example.com":                   {"v=spf1 redirect=%{d}.d.spf.example.com."},
			"exp.example.com":               {"v=spf1 exp=msg.example.com. -all"},
			"msg.example.com":               {"This is a test."},
			"e1.example.com":                {"v=spf1 -exists:%(ir).sbl.example.com ?all"},
			"e1e.example.com":               {"v=spf1 exists:foo%(ir).sbl.example.com ?all"},
			"e1t.example.com":               {"v=spf1 exists:foo%.sbl.example.com ?all"},
			"e1a.example.com":               {"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"},
			"e2.example.com":                {"v=spf1 -all exp=%{r}.example.com"},
			"e3.example.com":                {"v=spf1 -all exp=%{ir}.example.com"},
			"40.218.168.192.example.com":    {"Connections from %{c} not authorized."},
			long:                            {"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"},
			strings.Repeat(long+".", 8) + "example.com": {"Congratulations!  That was tricky."},
			"e4.example.com":    {"v=spf1 -all exp=e4msg.example.com"},
			"e4msg.example.com": {"%{c} is queried as %{ir}.%{v}.arpa"},
			"e5.example.com":    {"v=spf1 a:%{a}.example.com -all"},
			"e6.example.com":    {"v=spf1 -all exp=e6msg.example.com"},
			"e6msg.example.com": {"connect from %{p}"},
			"e7.example.com":    {"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"},
			"e8.example.com":    {"v=spf1 -all exp=msg8.%{D2}"},
			"msg8.example.com":  {"http://example.com/why.html?l=%{L}"},
			"e9.example.com":    {"v=spf1 a:%{H} -all"},
			"e10.example.com":   {"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"},
			"_spfh.example.com": {"v=spf1 -a:%{h} +all"},
			"e11.example.com":   {"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"},
			"e12.example.com":   {"v=spf1 exists:%{l2r+-}.user.%{d2}"},
		},
		nil,
		map[string][]string{
			"msgbas2x.cos.example.com":                  {"192.168.218.40"},
			"example.com":                               {"192.168.90.76"},
			"mx.example.com":                            {"192.168.218.41", "192.168.218.42"},
			"mx.e7.example.com":                         {"192.168.218.42"},
			"mx.e7.example.com.should.example.com":      {"127.0.0.2"},
			"mx.example.com.ok.example.com":             {"127.0.0.2"},
			"1.2.3.4.gladstone.philip.user.example.com": {"127.0.0.2"},
			"bar.foo.user.example.com":                  {"127.0.0.2"},
		},
		map[string][]string{
			"mx.example.com": {"cafe:babe::2", "cafe:babe::3"},
		},
		map[string][]string{
			"192.168.218.40": {"mx.example.com"},
			"192.168.218.41": {"mx.example.com"},
			"192.168.218.42": {"mx.example.com", "mx.e7.example.com"},
			"cafe:babe::1":   {"mx.example.com"},
			"cafe:babe::3":   {"mx.example.com"},
		},
	)

	for _, tc := range []struct {
		name, helo, host, mailfrom string
		want                       spf.Result
		explanation                string
	}{
		{"trailing-dot-domain", "msgbas2x.cos.example.com", "192.168.218.40", "test@example.com", spf.Pass, ""},
		{"trailing-dot-exp", "msgbas2x.cos.example.com", "192.168.218.40", "test@exp.example.com", spf.Fail, "This is a test."},
		{"exp-only-macro-char", "msgbas2x.cos.example.com", "192.168.218.40", "test@e2.example.com", spf.PermError, ""},
		{"invalid-macro-char", "msgbas2x.cos.example.com", "192.168.218.40", "test@e1.example.com", spf.PermError, ""},
		{"invalid-embedded-macro-char", "msgbas2x.cos.example.com", "192.168.218.40", "test@e1e.example.com", spf.PermError, ""},
		{"invalid-trailing-macro-char", "msgbas2x.cos.example.com", "192.168.218.40", "test@e1t.example.com", spf.PermError, ""},
		// macro-mania-in-domain (e1a) is left out: the suite expects a
		// lookup of "macro%percent  space%20url-space.example.com" to
		// pass, and go-spf queries only names IDNA's Lookup profile accepts
		// (no '%', no space), so that literal name is the record's own
		// error, a PermError (Open-Email/go-spf#4).
		{"exp-txt-macro-char", "msgbas2x.cos.example.com", "192.168.218.40", "test@e3.example.com", spf.Fail, "Connections from 192.168.218.40 not authorized."},
		{"domain-name-truncation", "msgbas2x.cos.example.com", "192.168.218.40", "test@" + long, spf.Fail, "Congratulations!  That was tricky."},
		{"v-macro-ip4", "msgbas2x.cos.example.com", "192.168.218.40", "test@e4.example.com", spf.Fail, "192.168.218.40 is queried as 40.218.168.192.in-addr.arpa"},
		// The suite spells the nibbles in uppercase; go-spf writes them in
		// lowercase, as RFC 7208 §7.4's own IPv6 example does.
		{"v-macro-ip6", "msgbas2x.cos.example.com", "CAFE:BABE::1", "test@e4.example.com", spf.Fail, "cafe:babe::1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.b.a.b.e.f.a.c.ip6.arpa"},
		{"undef-macro", "msgbas2x.cos.example.com", "CAFE:BABE::192.168.218.40", "test@e5.example.com", spf.PermError, ""},
		{"p-macro-ip4-novalid", "msgbas2x.cos.example.com", "192.168.218.40", "test@e6.example.com", spf.Fail, "connect from unknown"},
		{"p-macro-ip4-valid", "msgbas2x.cos.example.com", "192.168.218.41", "test@e6.example.com", spf.Fail, "connect from mx.example.com"},
		{"p-macro-ip6-novalid", "msgbas2x.cos.example.com", "CAFE:BABE::1", "test@e6.example.com", spf.Fail, "connect from unknown"},
		{"p-macro-ip6-valid", "msgbas2x.cos.example.com", "CAFE:BABE::3", "test@e6.example.com", spf.Fail, "connect from mx.example.com"},
		// The suite accepts pass or softfail. Both PTR names validate;
		// mx.e7.example.com is a subdomain of <domain>, which §7.3 says
		// SHOULD be used, and its name has the A record: pass.
		{"p-macro-multiple", "msgbas2x.cos.example.com", "192.168.218.42", "test@e7.example.com", spf.Pass, ""},
		{"upper-macro", "msgbas2x.cos.example.com", "192.168.218.42", "~jack&jill=up-a_b3.c@e8.example.com", spf.Fail, "http://example.com/why.html?l=~jack%26jill%3Dup-a_b3.c"},
		{"hello-macro", "msgbas2x.cos.example.com", "192.168.218.40", "test@e9.example.com", spf.Pass, ""},
		{"invalid-hello-macro", "JUMPIN' JUPITER", "192.168.218.40", "test@e9.example.com", spf.Fail, ""},
		{"hello-domain-literal", "[192.168.218.40]", "192.168.218.40", "test@e9.example.com", spf.Fail, ""},
		{"require-valid-helo", "OEMCOMPUTER", "1.2.3.4", "test@e10.example.com", spf.Fail, ""},
		{"macro-reverse-split-on-dash", "mail.example.com", "1.2.3.4", "philip-gladstone-test@e11.example.com", spf.Pass, ""},
		{"macro-multiple-delimiters", "mail.example.com", "1.2.3.4", "foo-bar+zip+quux@e12.example.com", spf.Pass, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domain := tc.mailfrom[strings.LastIndex(tc.mailfrom, "@")+1:]
			res, exp := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP(tc.host), domain, tc.mailfrom, tc.helo, r)
			if res != tc.want {
				t.Errorf("got %s, want %s", res, tc.want)
			}
			if tc.explanation != "" && exp != tc.explanation {
				t.Errorf("explanation: got %q, want %q", exp, tc.explanation)
			}
		})
	}
}
