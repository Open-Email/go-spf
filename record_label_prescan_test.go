package spf_test

import (
	"net"
	"strings"
	"testing"

	"github.com/Open-Email/go-spf"
)

// Pre-scanning cannot assume a macro's length or its resulting IDNA label.
// These are valid after expansion and RFC 7208 section 7.3 truncation.
func TestRecordLabelPrescanPreservesExpandedTargets(t *testing.T) {
	a63 := strings.Repeat("a", 63)
	longSuffix := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".example.com"
	dynamicSuffix := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 50)
	punySuffix := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 49)
	longSenderDomain := strings.Repeat("e", 62) + ".example.com"
	for _, tc := range []struct{ name, spec, sender, queried string }{
		{"long literal name", a63 + "." + longSuffix, "user@example.com", longSuffix},
		{"empty macro at label boundary", a63 + "%{l1-}.example.com", "user-@example.com", a63 + ".example.com"},
		{"punycode from macro", "xn--%{l}.example.com", "bcher-kva@example.com", "xn--bcher-kva.example.com"},
		{"macro expansion removes an oversized literal label", a63 + "a." + dynamicSuffix + ".%{o}", "user@longlongdomain.example.com", dynamicSuffix + ".longlongdomain.example.com"},
		{"macro expansion removes an invalid literal A-label", "xn--x." + punySuffix + ".%{o}", "user@" + longSenderDomain, punySuffix + "." + longSenderDomain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := resolverFull(map[string][]string{"example.com": {"v=spf1 exists:" + tc.spec + " -all"}}, nil, map[string][]string{tc.queried: {"127.0.0.2"}}, nil, nil)
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP("192.0.2.3"), "example.com", tc.sender, "", r); got != spf.Pass {
				t.Errorf("valid expanded target %q: got %s, want %s", tc.queried, got, spf.Pass)
			}
		})
	}
}

// When expansion leaves a record-authored invalid label in the query, it
// still reports PermError rather than treating it as invalid sender data.
func TestRecordLabelPrescanRetainsLookupValidation(t *testing.T) {
	for _, spec := range []string{strings.Repeat("a", 64) + ".%{d}", "xn--x.%{d}"} {
		t.Run(spec, func(t *testing.T) {
			r := resolverWith(map[string][]string{"example.com": {"v=spf1 exists:" + spec + " -all"}})
			if got := spf.CheckHostWithResolver(ctx, net.ParseIP("192.0.2.3"), "example.com", "user@example.com", "", r); got != spf.PermError {
				t.Errorf("unqueryable literal label: got %s, want %s", got, spf.PermError)
			}
		})
	}
}
