package spf_test

import (
	"net"
	"testing"

	"github.com/Open-Email/go-spf"
)

// Malformed terms must fail syntax checking even after an earlier match,
// and regardless of the client's address family (RFC 7208 section 4.6).
func TestMalformedRecordAnywhere(t *testing.T) {
	for _, term := range []string{
		"ip4:1.2.3.4/33", "ip4:1.2.3.4//32", "ip4:1.2.3.4:8080", "ip4:1.2.3",
		"ip4:1.2.3.4/032", "ip4:2001:db8::1", "ip4:", "ip4:1.2.3.4/+24",
		"ip6:::1/129", "ip6:::1//33", "ip6::CAFE::BABE", "ip6:192.0.2.1", "ip6:",
		"a:foo-bar", "mx:111.222.33.44", "exists:museum", "a:foo.-com", "a:foo.c0m!",
		"redirect=", "redirect=-all", "exp=", "exp=-all", "foo=%abc", "foo=%{z}",
		"a:ctrl.example.com\rptr", "ip4:192.0.2.3\n", "foo=nonascii\u00e9",
	} {
		for _, client := range []string{"192.0.2.3", "2001:db8::3"} {
			t.Run(client+"/"+term, func(t *testing.T) {
				r := resolverWith(map[string][]string{"example.com": {"v=spf1 +all " + term}})
				if got := spf.CheckHostWithResolver(ctx, net.ParseIP(client), "example.com", "u@example.com", "", r); got != spf.PermError {
					t.Errorf("+all followed by %q: got %s, want %s", term, got, spf.PermError)
				}
			})
		}
	}
}

// domain-end must end in an actual macro token or a literal dot/toplabel.
// An escaped percent followed by braces is literal text, not a macro token.
func TestDomainSpecEnd(t *testing.T) {
	for _, tc := range []struct {
		term string
		want spf.Result
	}{
		{"a:%{d}", spf.Pass},
		{"a:prefix.%{d}", spf.Pass},
		{"a:%{d}x.example", spf.Pass},
		{"a:foo.example.", spf.Pass},
		{"a:foo.123-456", spf.Pass},
		{"exists:x.%%", spf.Pass},
		{"exists:x.%_", spf.Pass},
		{"a:x.%-", spf.Pass},
		{"foo=", spf.Pass},
		{"a:%{d}x", spf.PermError},
		{"a:%%{d}", spf.PermError},
		{"a:%{d}.", spf.PermError},
		{"a:foo.123", spf.PermError},
		{"a:foo.-example", spf.PermError},
		{"a:foo.example-", spf.PermError},
	} {
		t.Run(tc.term, func(t *testing.T) {
			r := resolverWith(map[string][]string{"example.com": {"v=spf1 +all " + tc.term}})
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP("192.0.2.3"), "example.com", "u@example.com", "", r); got != tc.want {
				t.Errorf("+all followed by %q: got %s, want %s", tc.term, got, tc.want)
			}
		})
	}
}

func TestInitialSingleLabelDomain(t *testing.T) {
	r := resolverWith(map[string][]string{"localhost": {"v=spf1 +all"}})
	if got := spf.CheckHostWithResolver(ctx, net.ParseIP("192.0.2.3"), "localhost", "u@localhost", "localhost", r); got != spf.None {
		t.Errorf("single-label initial domain: got %s, want %s", got, spf.None)
	}
}

// A quoted local part may itself begin with '@'. Callers such as go-smtp
// can pass it decoded, so only an empty part before the LAST '@' calls for
// the RFC 7208 section 4.3 postmaster fallback.
func TestPostmasterFallbackPreservesLeadingAtLocalPart(t *testing.T) {
	r := resolverWith(map[string][]string{
		"example.com":     {"v=spf1 -all exp=why.example.com"},
		"why.example.com": {"%{s}|%{l}|%{o}"},
	})
	for _, tc := range []struct {
		sender, wantSender, wantLocal string
	}{
		{"@example.com", "postmaster@example.com", "postmaster"},
		{"@@example.com", "@@example.com", "@"},
		{"@user@example.com", "@user@example.com", "@user"},
		{`"@user"@example.com`, `"@user"@example.com`, `"@user"`},
		{`"@"@example.com`, `"@"@example.com`, `"@"`},
		{"user@example.com", "user@example.com", "user"},
	} {
		t.Run(tc.sender, func(t *testing.T) {
			result, explanation := spf.CheckHostWithExplanationAndResolver(ctx, net.ParseIP("192.0.2.3"), "example.com", tc.sender, "", r)
			want := tc.wantSender + "|" + tc.wantLocal + "|example.com"
			if result != spf.Fail || explanation != want {
				t.Errorf("got %s, %q; want %s, %q", result, explanation, spf.Fail, want)
			}
		})
	}
}
