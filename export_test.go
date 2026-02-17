package spf

import (
	"context"
	"net"
	"testing"
)

// internalMockResolver is a minimal Resolver used by white-box tests in this
// file. It does not make real network calls.
type internalMockResolver struct {
	txt  map[string][]string
	mx   map[string][]string
	a    map[string][]string
	aaaa map[string][]string
	ptr  map[string][]string
}

func (m *internalMockResolver) LookupTXT(_ context.Context, domain string) ([]string, error) {
	return m.txt[domain], nil
}
func (m *internalMockResolver) LookupMX(_ context.Context, domain string) ([]string, error) {
	return m.mx[domain], nil
}
func (m *internalMockResolver) LookupA(_ context.Context, domain string) ([]net.IP, error) {
	var ips []net.IP
	for _, s := range m.a[domain] {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
func (m *internalMockResolver) LookupAAAA(_ context.Context, domain string) ([]net.IP, error) {
	var ips []net.IP
	for _, s := range m.aaaa[domain] {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
func (m *internalMockResolver) LookupPTR(_ context.Context, ip net.IP) ([]string, error) {
	return m.ptr[ip.String()], nil
}

func TestPTR(t *testing.T) {
	ctx := context.Background()

	t.Run("no match returns internalNoMatch", func(t *testing.T) {
		mock := &internalMockResolver{
			ptr: map[string][]string{
				"223.204.237.87": {"unrelated.host.example."},
			},
			a: map[string][]string{
				"unrelated.host.example.": {"1.2.3.4"},
			},
		}
		c := check{ctx: ctx, cnt: 0, resolver: mock}
		ip := net.ParseIP("223.204.237.87")
		if got := c.checkPTR(ip, "example.com", ""); got != internalNoMatch {
			t.Errorf("checkPTR: got %s, want %s", got, internalNoMatch)
		}
	})

	t.Run("match returns Pass", func(t *testing.T) {
		mock := &internalMockResolver{
			ptr: map[string][]string{
				"1.2.3.4": {"mail.example.com"},
			},
			a: map[string][]string{
				"mail.example.com": {"1.2.3.4"},
			},
		}
		c := check{ctx: ctx, cnt: 0, resolver: mock}
		ip := net.ParseIP("1.2.3.4")
		if got := c.checkPTR(ip, "mail.example.com", ""); got != Pass {
			t.Errorf("checkPTR: got %s, want %s", got, Pass)
		}
	})

	t.Run("IPv6 validates with AAAA", func(t *testing.T) {
		mock := &internalMockResolver{
			ptr: map[string][]string{
				"2001:db8::1": {"mail.example.com"},
			},
			aaaa: map[string][]string{
				"mail.example.com": {"2001:db8::1"},
			},
		}
		c := check{ctx: ctx, cnt: 0, resolver: mock}
		ip := net.ParseIP("2001:db8::1")
		if got := c.checkPTR(ip, "mail.example.com", ""); got != Pass {
			t.Errorf("checkPTR IPv6: got %s, want %s", got, Pass)
		}
	})
}

// Macro exports macro for testing
func Macro(m string, ip net.IP, domain, sender, helo string) string {
	if sender == "" {
		sender = "postmaster@" + helo
	}

	c := check{
		ctx:      context.Background(),
		cnt:      0,
		resolver: DefaultResolver,
	}

	r, _ := c.macro(m, ip, domain, sender, helo)
	return r
}

// ParseSPF exports parseSPF for testing
func ParseSPF(spf string) []interface{} {
	return parseSPF(spf)
}

func TestReverseIPArpa(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"1.2.3.4", "4.3.2.1.in-addr.arpa."},
		{"192.168.1.100", "100.1.168.192.in-addr.arpa."},
		{"8.8.8.8", "8.8.8.8.in-addr.arpa."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
		{"::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP in test case: %s", tt.ip)
		}
		if got := reverseIPArpa(ip); got != tt.want {
			t.Errorf("reverseIPArpa(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}
