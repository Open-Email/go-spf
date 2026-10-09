package spf_test

import (
	"context"
	spf "github.com/Open-Email/go-spf"
	"net"
	"testing"
)

func TestSMTPUTF8DNSBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, domain, policy string }{
		{"initial", "BÜCHER.de.", "v=spf1 +all"},
		{"include", "example.test", "v=spf1 include:bücher.de -all"},
		{"redirect", "example.test", "v=spf1 redirect=bücher.de"},
		{"include macro", "example.test", "v=spf1 include:%{o} -all"},
		{"redirect macro", "example.test", "v=spf1 redirect=%{o}"},
		{"a macro", "example.test", "v=spf1 a:%{o} -all"},
		{"mx macro", "example.test", "v=spf1 mx:%{o} -all"},
		{"exists macro", "example.test", "v=spf1 exists:%{o} -all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &mockResolver{txt: map[string][]string{"example.test": {tc.policy}, "xn--bcher-kva.de": {"v=spf1 +all"}}, a: map[string][]string{"xn--bcher-kva.de": {"192.0.2.1"}}, mx: map[string][]string{"xn--bcher-kva.de": {"BÜCHER.de."}}}
			if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), tc.domain, "José@bücher.de", "bücher.de", r); got != spf.Pass {
				t.Fatalf("got %s", got)
			}
		})
	}
}

// RFC 7208 §4.3: a malformed initial domain is None, not PermError.
func TestSMTPUTF8MalformedInitialDomainIsNone(t *testing.T) {
	if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), "bad\u200d.test", "a@test", "test", &mockResolver{}); got != spf.None {
		t.Fatalf("got %s", got)
	}
}

// RFC 7208 §5.2 and §6.1: a malformed include or redirect target is PermError.
func TestSMTPUTF8MalformedTargetIsPermError(t *testing.T) {
	for _, policy := range []string{"v=spf1 include:bad\u200d.test -all", "v=spf1 redirect=bad\u200d.test"} {
		r := &mockResolver{txt: map[string][]string{"example.test": {policy}}}
		if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "a@example.test", "example.test", r); got != spf.PermError {
			t.Fatalf("%s: got %s", policy, got)
		}
	}
}

// RFC 7505: a null MX answer is skipped by the mx mechanism, not a TempError.
func TestSMTPUTF8NullMXIsSkipped(t *testing.T) {
	r := &mockResolver{txt: map[string][]string{"example.test": {"v=spf1 mx -all"}}, mx: map[string][]string{"example.test": {"."}}}
	if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "a@example.test", "example.test", r); got != spf.Fail {
		t.Fatalf("got %s", got)
	}
}

func TestSMTPUTF8MappedLabels(t *testing.T) {
	r := &mockResolver{txt: map[string][]string{"xn--bcher-kva.de": {"v=spf1 +all"}}}
	if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), "bücher。de", "a@test", "test", r); got != spf.Pass {
		t.Fatalf("mapped separator: %s", got)
	}
	if got := spf.CheckHostWithResolver(context.Background(), net.ParseIP("192.0.2.1"), "\u00ad.de", "a@test", "test", r); got != spf.None {
		t.Fatalf("empty label: %s", got)
	}
}
