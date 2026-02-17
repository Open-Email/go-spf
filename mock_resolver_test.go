package spf_test

import (
	"context"
	"fmt"
	"net"
)

// mockResolver implements spf.Resolver using in-memory DNS data for testing.
type mockResolver struct {
	txt        map[string][]string
	mx         map[string][]string
	a          map[string][]string
	aaaa       map[string][]string
	ptr        map[string][]string
	err        error           // when non-nil, all lookups return this error
	errDomains map[string]bool // when set, lookups for this domain return error
}

func (m *mockResolver) LookupTXT(_ context.Context, domain string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.errDomains != nil && m.errDomains[domain] {
		return nil, newDNSError("temp error")
	}
	return m.txt[domain], nil
}

func (m *mockResolver) LookupMX(_ context.Context, domain string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.mx[domain], nil
}

func (m *mockResolver) LookupA(_ context.Context, domain string) ([]net.IP, error) {
	if m.err != nil {
		return nil, m.err
	}
	var ips []net.IP
	for _, s := range m.a[domain] {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func (m *mockResolver) LookupAAAA(_ context.Context, domain string) ([]net.IP, error) {
	if m.err != nil {
		return nil, m.err
	}
	var ips []net.IP
	for _, s := range m.aaaa[domain] {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func (m *mockResolver) LookupPTR(_ context.Context, ip net.IP) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ptr[ip.String()], nil
}

// newMockResolver returns a pre-populated mock resolver with fixture data that
// mirrors the SPF policies exercised by the test suite, without requiring real
// network access.
func newMockResolver() *mockResolver {
	return &mockResolver{
		txt: map[string][]string{
			"example.com":          {"v=spf1 ip4:188.93.126.226 ip4:87.237.205.46 ~all"},
			"mail.example.com":     {"v=spf1 ip4:188.93.126.226 ~all"},
			"smtp.example.com":     {"v=spf1 ip4:188.93.126.226 ip4:87.237.205.46 ~all"},
			"gmail.com":            {"v=spf1 ~all"},
			"hotmail.com":          {"v=spf1 ~all"},
			"outbound.example.com": {"v=spf1 ip4:87.237.205.46 ~all"},
			"teicee.fr":            {"v=spf1 mx ~all"},
			// example.invalid — intentionally absent (returns NONE)
		},
		mx: map[string][]string{
			"teicee.fr": {"mail.teicee.fr."},
		},
		a: map[string][]string{
			"mail.teicee.fr.": {"1.2.3.4"},
		},
		ptr: map[string][]string{
			"223.204.237.87": {"unrelated.host.example."},
		},
	}
}

// errResolver returns a resolver that always fails with the given error.
func errResolver(e error) *mockResolver {
	return &mockResolver{err: e}
}

// dnsError is a simple error type that mimics a DNS network error.
type dnsError struct{ msg string }

func (e *dnsError) Error() string { return e.msg }

func newDNSError(format string, args ...interface{}) error {
	return &dnsError{msg: fmt.Sprintf(format, args...)}
}

// resolverWith is a convenience builder that starts from an empty mockResolver
// and lets callers supply only the records they need for a focused test.
func resolverWith(txt map[string][]string) *mockResolver {
	return &mockResolver{
		txt:  txt,
		mx:   map[string][]string{},
		a:    map[string][]string{},
		aaaa: map[string][]string{},
		ptr:  map[string][]string{},
	}
}

// resolverFull constructs a fully-specified mockResolver from all record types.
func resolverFull(
	txt map[string][]string,
	mx map[string][]string,
	a map[string][]string,
	aaaa map[string][]string,
	ptr map[string][]string,
) *mockResolver {
	if txt == nil {
		txt = map[string][]string{}
	}
	if mx == nil {
		mx = map[string][]string{}
	}
	if a == nil {
		a = map[string][]string{}
	}
	if aaaa == nil {
		aaaa = map[string][]string{}
	}
	if ptr == nil {
		ptr = map[string][]string{}
	}
	return &mockResolver{txt: txt, mx: mx, a: a, aaaa: aaaa, ptr: ptr}
}
