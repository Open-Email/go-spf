package spf_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Open-Email/go-spf"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var ctx = context.Background()

type testCase struct {
	name   string
	ip     string
	domain string
	sender string
	want   spf.Result
	r      *mockResolver
}

func runCases(t *testing.T, cases []testCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid IP %q", tc.ip)
			}
			got := spf.CheckHostWithResolver(ctx, ip, tc.domain, tc.sender, "", tc.r)
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestLookup — LookupSPF basics
// ---------------------------------------------------------------------------

func TestLookup(t *testing.T) {
	orig := spf.DefaultResolver
	spf.DefaultResolver = newMockResolver()
	defer func() { spf.DefaultResolver = orig }()

	if s, r := spf.LookupSPF(ctx, "example.com"); s == "" {
		t.Fatal("SPF to example.com failed", r.String())
	}
	if s, r := spf.LookupSPF(ctx, "mail.example.com"); s == "" {
		t.Fatal("SPF to mail.example.com failed", r.String())
	}
	if _, r := spf.LookupSPF(ctx, "example.invalid"); r != spf.None {
		t.Fatal("SPF on invalid domain should be NONE, returned", r.String())
	}
}

// TestLookupMultipleSPFRecords verifies that two v=spf1 TXT records → PermError (RFC §4.5).
func TestLookupMultipleSPFRecords(t *testing.T) {
	r := resolverWith(map[string][]string{
		"dup.example.com": {"v=spf1 ip4:1.2.3.4 ~all", "v=spf1 ip4:5.6.7.8 -all"},
	})
	orig := spf.DefaultResolver
	spf.DefaultResolver = r
	defer func() { spf.DefaultResolver = orig }()

	if _, got := spf.LookupSPF(ctx, "dup.example.com"); got != spf.PermError {
		t.Errorf("duplicate SPF records: want PermError, got %s", got)
	}
}

// TestLookupTempError verifies that a DNS failure in LookupSPF returns TempError.
func TestLookupTempError(t *testing.T) {
	orig := spf.DefaultResolver
	spf.DefaultResolver = errResolver(newDNSError("timeout"))
	defer func() { spf.DefaultResolver = orig }()

	if _, got := spf.LookupSPF(ctx, "any.example.com"); got != spf.TempError {
		t.Errorf("DNS error: want TempError, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// TestCNAME — MX-with-CNAME resolution path
// ---------------------------------------------------------------------------

func TestCNAME(t *testing.T) {
	ip := net.ParseIP("123.123.123.123")
	spf.CheckHostWithResolver(ctx, ip, "teicee.fr", "name@teicee.fr", "", newMockResolver())
}

// ---------------------------------------------------------------------------
// TestQualifiers — all four qualifiers on the "all" mechanism (always matches)
// ---------------------------------------------------------------------------

func TestQualifiers(t *testing.T) {
	ip := "1.2.3.4"
	cases := []testCase{
		{
			name: "all +pass", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 +all"}}),
		},
		{
			name: "all -fail", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 -all"}}),
		},
		{
			name: "all ~softfail", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Softfail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ~all"}}),
		},
		{
			name: "all ?neutral", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Neutral,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ?all"}}),
		},
		{
			name: "ip4 +pass (explicit)", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 +ip4:1.2.3.4 -all"}}),
		},
		{
			name: "ip4 pass (implicit +)", ip: ip, domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:1.2.3.4 -all"}}),
		},
		{
			name: "ip4 no match then -all", ip: "9.9.9.9", domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:1.2.3.4 -all"}}),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestIP4Mechanism
// ---------------------------------------------------------------------------

func TestIP4Mechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "exact match", ip: "10.0.0.1", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:10.0.0.1 -all"}}),
		},
		{
			name: "CIDR match", ip: "10.0.0.100", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:10.0.0.0/24 -all"}}),
		},
		{
			name: "CIDR miss", ip: "10.0.1.1", domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:10.0.0.0/24 -all"}}),
		},
		{
			name: "IPv6 client skips ip4", ip: "2001:db8::1", domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip4:10.0.0.1 -all"}}),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestIP6Mechanism
// ---------------------------------------------------------------------------

func TestIP6Mechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "exact match", ip: "2001:db8::1", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip6:2001:db8::1 -all"}}),
		},
		{
			name: "CIDR match", ip: "2001:db8::ff", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip6:2001:db8::/32 -all"}}),
		},
		{
			name: "CIDR miss", ip: "2001:db9::1", domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip6:2001:db8::/32 -all"}}),
		},
		{
			name: "IPv4 client skips ip6", ip: "1.2.3.4", domain: "d.example", sender: "u@d.example", want: spf.Fail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ip6:2001:db8::1 -all"}}),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestAMechanism
// ---------------------------------------------------------------------------

func TestAMechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "a matches sender domain IPv4", ip: "5.5.5.5", domain: "a.example", sender: "u@a.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"a.example": {"v=spf1 a -all"}},
				nil,
				map[string][]string{"a.example": {"5.5.5.5"}},
				nil, nil,
			),
		},
		{
			name: "a with explicit domain", ip: "6.6.6.6", domain: "a.example", sender: "u@a.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"a.example": {"v=spf1 a:other.example -all"}},
				nil,
				map[string][]string{"other.example": {"6.6.6.6"}},
				nil, nil,
			),
		},
		{
			name: "a with explicit domain and CIDR", ip: "9.9.9.50", domain: "a.example", sender: "u@a.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"a.example": {"v=spf1 a:a.example/24 -all"}},
				nil,
				map[string][]string{"a.example": {"9.9.9.1"}},
				nil, nil,
			),
		},
		{
			name: "a miss", ip: "7.7.7.7", domain: "a.example", sender: "u@a.example", want: spf.Fail,
			r: resolverFull(
				map[string][]string{"a.example": {"v=spf1 a -all"}},
				nil,
				map[string][]string{"a.example": {"5.5.5.5"}},
				nil, nil,
			),
		},
		{
			name: "a matches IPv6 sender", ip: "2001:db8::5", domain: "a.example", sender: "u@a.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"a.example": {"v=spf1 a -all"}},
				nil, nil,
				map[string][]string{"a.example": {"2001:db8::5"}},
				nil,
			),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestMXMechanism
// ---------------------------------------------------------------------------

func TestMXMechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "mx matches", ip: "20.20.20.20", domain: "mx.example", sender: "u@mx.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"mx.example": {"v=spf1 mx -all"}},
				map[string][]string{"mx.example": {"mail.mx.example."}},
				map[string][]string{"mail.mx.example": {"20.20.20.20"}},
				nil, nil,
			),
		},
		{
			name: "mx miss", ip: "99.99.99.99", domain: "mx.example", sender: "u@mx.example", want: spf.Fail,
			r: resolverFull(
				map[string][]string{"mx.example": {"v=spf1 mx -all"}},
				map[string][]string{"mx.example": {"mail.mx.example."}},
				map[string][]string{"mail.mx.example": {"20.20.20.20"}},
				nil, nil,
			),
		},
		{
			name: "mx explicit domain", ip: "30.30.30.30", domain: "mx.example", sender: "u@mx.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"mx.example": {"v=spf1 mx:relay.example -all"}},
				map[string][]string{"relay.example": {"mail.relay.example."}},
				map[string][]string{"mail.relay.example": {"30.30.30.30"}},
				nil, nil,
			),
		},
		{
			name: "mx with explicit domain and CIDR", ip: "40.40.40.100", domain: "mx.example", sender: "u@mx.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"mx.example": {"v=spf1 mx:mx.example/24 -all"}},
				map[string][]string{"mx.example": {"mail.mx.example."}},
				map[string][]string{"mail.mx.example": {"40.40.40.1"}},
				nil, nil,
			),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestPTRMechanism
// ---------------------------------------------------------------------------

func TestPTRMechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "ptr exact match", ip: "1.2.3.4", domain: "ptr.example", sender: "u@ptr.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"ptr.example": {"v=spf1 ptr:mail.ptr.example -all"}},
				nil,
				map[string][]string{"mail.ptr.example": {"1.2.3.4"}},
				nil,
				map[string][]string{"1.2.3.4": {"mail.ptr.example"}},
			),
		},
		{
			name: "ptr mismatch domain", ip: "1.2.3.4", domain: "ptr.example", sender: "u@ptr.example", want: spf.Fail,
			r: resolverFull(
				map[string][]string{"ptr.example": {"v=spf1 ptr -all"}},
				nil,
				map[string][]string{"host.other.example.": {"1.2.3.4"}},
				nil,
				map[string][]string{"1.2.3.4": {"host.other.example."}},
			),
		},
		{
			name: "ptr no record", ip: "5.5.5.5", domain: "ptr.example", sender: "u@ptr.example", want: spf.Fail,
			r: resolverFull(
				map[string][]string{"ptr.example": {"v=spf1 ptr -all"}},
				nil, nil, nil,
				map[string][]string{},
			),
		},
		{
			name: "ptr DNS error fails to match and continues", ip: "1.2.3.4", domain: "ptr.example", sender: "u@ptr.example", want: spf.Pass,
			r: &mockResolver{
				txt:    map[string][]string{"ptr.example": {"v=spf1 ptr ip4:1.2.3.4 -all"}},
				ptrErr: newDNSError("SERVFAIL"),
			},
		},
		{
			name: "ptr DNS error falls through to -all", ip: "1.2.3.4", domain: "ptr.example", sender: "u@ptr.example", want: spf.Fail,
			r: &mockResolver{
				txt:    map[string][]string{"ptr.example": {"v=spf1 ptr -all"}},
				ptrErr: newDNSError("SERVFAIL"),
			},
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestIncludeMechanism
// ---------------------------------------------------------------------------

func TestIncludeMechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "include pass", ip: "50.50.50.50", domain: "outer.example", sender: "u@outer.example", want: spf.Pass,
			r: resolverWith(map[string][]string{
				"outer.example": {"v=spf1 include:inner.example -all"},
				"inner.example": {"v=spf1 ip4:50.50.50.50 -all"},
			}),
		},
		{
			name: "include fail continues", ip: "99.99.99.99", domain: "outer.example", sender: "u@outer.example", want: spf.Fail,
			r: resolverWith(map[string][]string{
				"outer.example": {"v=spf1 include:inner.example -all"},
				"inner.example": {"v=spf1 ip4:50.50.50.50 -all"},
			}),
		},
		{
			name: "include nested", ip: "60.60.60.60", domain: "outer.example", sender: "u@outer.example", want: spf.Pass,
			r: resolverWith(map[string][]string{
				"outer.example": {"v=spf1 include:mid.example -all"},
				"mid.example":   {"v=spf1 include:inner.example -all"},
				"inner.example": {"v=spf1 ip4:60.60.60.60 -all"},
			}),
		},
		{
			name: "include none permerror", ip: "1.2.3.4", domain: "outer.example", sender: "u@outer.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"outer.example": {"v=spf1 include:missing.example -all"},
			}),
		},
	}
	runCases(t, cases)
}

// TestIncludeTempErrorPropagation verifies that a TempError in an included mechanism
// is propagated immediately (RFC §5.2), rather than being treated as "no match".
func TestIncludeTempErrorPropagation(t *testing.T) {
	r := resolverWith(map[string][]string{
		"domain.com": {"v=spf1 include:broken.com -all"},
	})
	r.errDomains = map[string]bool{"broken.com": true}

	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "domain.com", "sender@domain.com", "", r)
	if got != spf.TempError {
		t.Errorf("expected TempError from include, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// TestRedirectModifier
// ---------------------------------------------------------------------------

func TestRedirectModifier(t *testing.T) {
	cases := []testCase{
		{
			name: "redirect pass", ip: "70.70.70.70", domain: "redir.example", sender: "u@redir.example", want: spf.Pass,
			r: resolverWith(map[string][]string{
				"redir.example":  {"v=spf1 redirect=target.example"},
				"target.example": {"v=spf1 ip4:70.70.70.70 -all"},
			}),
		},
		{
			name: "redirect fail", ip: "99.99.99.99", domain: "redir.example", sender: "u@redir.example", want: spf.Fail,
			r: resolverWith(map[string][]string{
				"redir.example":  {"v=spf1 redirect=target.example"},
				"target.example": {"v=spf1 -all"},
			}),
		},
		{
			name: "redirect softfail", ip: "99.99.99.99", domain: "redir.example", sender: "u@redir.example", want: spf.Softfail,
			r: resolverWith(map[string][]string{
				"redir.example":  {"v=spf1 redirect=target.example"},
				"target.example": {"v=spf1 ~all"},
			}),
		},
		{
			name: "redirect execution order", ip: "1.2.3.4", domain: "domain.com", sender: "sender@domain.com", want: spf.Pass,
			r: resolverWith(map[string][]string{
				"domain.com": {"v=spf1 redirect=other.com +all"},
				"other.com":  {"v=spf1 -all"},
			}),
		},
		{
			name: "redirect none permerror", ip: "1.2.3.4", domain: "redir.example", sender: "u@redir.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"redir.example": {"v=spf1 redirect=missing.example"},
			}),
		},
		{
			name: "redirect non-spf txt permerror", ip: "1.2.3.4", domain: "redir.example", sender: "u@redir.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"redir.example":  {"v=spf1 redirect=target.example"},
				"target.example": {"not-an-spf-record"},
			}),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestExistsMechanism
// ---------------------------------------------------------------------------

func TestExistsMechanism(t *testing.T) {
	cases := []testCase{
		{
			name: "exists hit", ip: "1.2.3.4", domain: "ex.example", sender: "u@ex.example", want: spf.Pass,
			r: resolverFull(
				map[string][]string{"ex.example": {"v=spf1 exists:check.ex.example -all"}},
				nil,
				map[string][]string{"check.ex.example": {"127.0.0.2"}},
				nil, nil,
			),
		},
		{
			name: "exists miss", ip: "1.2.3.4", domain: "ex.example", sender: "u@ex.example", want: spf.Fail,
			r: resolverFull(
				map[string][]string{"ex.example": {"v=spf1 exists:check.ex.example -all"}},
				nil,
				map[string][]string{},
				nil, nil,
			),
		},
	}
	runCases(t, cases)
}

// TestExistsDNSError verifies that a DNS error on exists → TempError (RFC §5.7).
func TestExistsDNSError(t *testing.T) {
	r := resolverWith(map[string][]string{
		"domain.com": {"v=spf1 exists:check.domain.com -all"},
	})
	r.errDomains = map[string]bool{"check.domain.com": true}
	// errDomains only affects LookupTXT; we need LookupA to fail too.
	// Use a custom resolver that fails on LookupA for the exists domain.
	customR := &existsErrResolver{
		mockResolver: resolverWith(map[string][]string{
			"domain.com": {"v=spf1 exists:check.domain.com -all"},
		}),
		errDomain: "check.domain.com",
	}

	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "domain.com", "sender@domain.com", "", customR)
	if got != spf.TempError {
		t.Errorf("exists DNS error: want TempError, got %s", got)
	}
}

// existsErrResolver wraps mockResolver but returns errors for LookupA on a specific domain.
type existsErrResolver struct {
	*mockResolver
	errDomain string
}

func (r *existsErrResolver) LookupA(ctx context.Context, domain string) ([]net.IP, error) {
	if domain == r.errDomain {
		return nil, newDNSError("lookup failed")
	}
	return r.mockResolver.LookupA(ctx, domain)
}

// ---------------------------------------------------------------------------
// TestDNSLookupLimit — RFC §4.6.4: >10 DNS-querying mechanisms → PermError
// ---------------------------------------------------------------------------

func TestDNSLookupLimit(t *testing.T) {
	txt := map[string][]string{}
	for i := 0; i < 11; i++ {
		curr := fmt.Sprintf("d%d.example", i)
		next := fmt.Sprintf("d%d.example", i+1)
		txt[curr] = []string{"v=spf1 include:" + next + " -all"}
	}
	txt["d11.example"] = []string{"v=spf1 ip4:1.2.3.4 -all"}

	r := resolverWith(txt)
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "d0.example", "u@d0.example", "", r)
	if got != spf.PermError {
		t.Errorf("expected PermError from DNS lookup limit, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// Resilience tests — malicious / malformed SPF records must never loop
// ---------------------------------------------------------------------------

func TestSelfReferentialInclude(t *testing.T) {
	r := resolverWith(map[string][]string{
		"loop.example": {"v=spf1 include:loop.example -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "loop.example", "u@loop.example", "", r)
	if got != spf.PermError {
		t.Errorf("self-referential include: want PermError, got %s", got)
	}
}

func TestSelfReferentialRedirect(t *testing.T) {
	r := resolverWith(map[string][]string{
		"loop.example": {"v=spf1 redirect=loop.example"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "loop.example", "u@loop.example", "", r)
	if got != spf.PermError {
		t.Errorf("self-referential redirect: want PermError, got %s", got)
	}
}

func TestMutualIncludeCycle(t *testing.T) {
	r := resolverWith(map[string][]string{
		"a.example": {"v=spf1 include:b.example -all"},
		"b.example": {"v=spf1 include:a.example -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "a.example", "u@a.example", "", r)
	if got != spf.PermError {
		t.Errorf("mutual include cycle: want PermError, got %s", got)
	}
}

func TestMutualRedirectCycle(t *testing.T) {
	r := resolverWith(map[string][]string{
		"a.example": {"v=spf1 redirect=b.example"},
		"b.example": {"v=spf1 redirect=a.example"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "a.example", "u@a.example", "", r)
	if got != spf.PermError {
		t.Errorf("mutual redirect cycle: want PermError, got %s", got)
	}
}

func TestIncludeRedirectMixedCycle(t *testing.T) {
	r := resolverWith(map[string][]string{
		"a.example": {"v=spf1 include:b.example -all"},
		"b.example": {"v=spf1 redirect=a.example"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "a.example", "u@a.example", "", r)
	if got != spf.PermError {
		t.Errorf("include/redirect mixed cycle: want PermError, got %s", got)
	}
}

func TestExcessiveMXRecords(t *testing.T) {
	mxRecords := make([]string, 15)
	aRecords := map[string][]string{}
	for i := 0; i < 15; i++ {
		host := fmt.Sprintf("mx%d.evil.example.", i)
		mxRecords[i] = host
		aRecords[host] = []string{"10.0.0.1"}
	}
	r := resolverFull(
		map[string][]string{"evil.example": {"v=spf1 mx -all"}},
		map[string][]string{"evil.example": mxRecords},
		aRecords,
		nil, nil,
	)
	ip := net.ParseIP("10.0.0.1")
	got := spf.CheckHostWithResolver(ctx, ip, "evil.example", "u@evil.example", "", r)
	if got != spf.PermError {
		t.Errorf("excessive MX records: want PermError, got %s", got)
	}
}

func TestExcessivePTRRecords(t *testing.T) {
	ptrRecords := make([]string, 20)
	aRecords := map[string][]string{}
	for i := 0; i < 20; i++ {
		host := fmt.Sprintf("ptr%d.evil.example", i)
		ptrRecords[i] = host
		aRecords[host] = []string{"1.2.3.4"}
	}
	r := resolverFull(
		map[string][]string{"evil.example": {"v=spf1 ptr -all"}},
		nil, aRecords, nil,
		map[string][]string{"1.2.3.4": ptrRecords},
	)
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "evil.example", "u@evil.example", "", r)
	if got != spf.Pass {
		t.Errorf("excessive PTR records: want Pass (capped), got %s", got)
	}
}

func TestDeepRedirectChain(t *testing.T) {
	txt := map[string][]string{}
	for i := 0; i < 20; i++ {
		curr := fmt.Sprintf("r%d.example", i)
		next := fmt.Sprintf("r%d.example", i+1)
		txt[curr] = []string{"v=spf1 redirect=" + next}
	}
	txt["r20.example"] = []string{"v=spf1 +all"}

	r := resolverWith(txt)
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "r0.example", "u@r0.example", "", r)
	if got != spf.PermError {
		t.Errorf("deep redirect chain: want PermError, got %s", got)
	}
}

func TestVoidLookupLimit(t *testing.T) {
	cases := []testCase{
		{
			name: "two void lookups allowed", ip: "1.2.3.4", domain: "v.example", sender: "u@v.example", want: spf.Pass,
			r: resolverWith(map[string][]string{
				"v.example": {"v=spf1 a:n1.example mx:n2.example ip4:1.2.3.4 -all"},
			}),
		},
		{
			name: "three void a lookups permerror", ip: "1.2.3.4", domain: "v.example", sender: "u@v.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"v.example": {"v=spf1 a:n1.example a:n2.example a:n3.example ip4:1.2.3.4 -all"},
			}),
		},
		{
			name: "three void mx lookups permerror", ip: "1.2.3.4", domain: "v.example", sender: "u@v.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"v.example": {"v=spf1 mx:n1.example mx:n2.example mx:n3.example ip4:1.2.3.4 -all"},
			}),
		},
		{
			name: "mixed void a and mx lookups exceeding limit permerror", ip: "1.2.3.4", domain: "v.example", sender: "u@v.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"v.example": {"v=spf1 a:n1.example a:n2.example a:n3.example mx:n4.example ip4:1.2.3.4 -all"},
			}),
		},
		{
			name: "void ipv6 aaaa lookups exceeding limit permerror", ip: "2001:db8::1", domain: "v.example", sender: "u@v.example", want: spf.PermError,
			r: resolverWith(map[string][]string{
				"v.example": {"v=spf1 a:n1.example a:n2.example a:n3.example ip6:2001:db8::1 -all"},
			}),
		},
	}
	runCases(t, cases)
}

func TestLargeNumberOfMechanisms(t *testing.T) {
	spfRecord := "v=spf1"
	for i := 1; i < 100; i++ {
		spfRecord += fmt.Sprintf(" ip4:10.0.%d.0/24", i%256)
	}
	spfRecord += " -all"

	r := resolverWith(map[string][]string{
		"big.example": {spfRecord},
	})
	ip := net.ParseIP("10.0.50.1")
	got := spf.CheckHostWithResolver(ctx, ip, "big.example", "u@big.example", "", r)
	if got != spf.Pass {
		t.Errorf("many ip4 mechanisms: want Pass, got %s", got)
	}
}

func TestEmptySPFRecord(t *testing.T) {
	r := resolverWith(map[string][]string{
		"empty.example": {"v=spf1"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "empty.example", "u@empty.example", "", r)
	if got != spf.Neutral {
		t.Errorf("empty SPF record: want Neutral, got %s", got)
	}
}

func TestDuplicateRedirectModifier(t *testing.T) {
	r := resolverWith(map[string][]string{
		"dup.example": {"v=spf1 redirect=a.example redirect=b.example"},
		"a.example":   {"v=spf1 +all"},
		"b.example":   {"v=spf1 +all"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "dup.example", "u@dup.example", "", r)
	if got != spf.PermError {
		t.Errorf("duplicate redirect: want PermError, got %s", got)
	}
}

// TestDuplicateExpModifier verifies that two exp= modifiers → PermError.
func TestDuplicateExpModifier(t *testing.T) {
	r := resolverWith(map[string][]string{
		"dup.example": {"v=spf1 exp=a.example exp=b.example -all"},
		"a.example":   {"first explanation"},
		"b.example":   {"second explanation"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "dup.example", "u@dup.example", "", r)
	if got != spf.PermError {
		t.Errorf("duplicate exp: want PermError, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// TestNoSPFRecord — domain with no SPF → None
// ---------------------------------------------------------------------------

func TestNoSPFRecord(t *testing.T) {
	r := resolverWith(map[string][]string{})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "nospr.example", "u@nospr.example", "", r)
	if got != spf.None {
		t.Errorf("expected None for missing SPF record, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// TestTempErrorPropagation — DNS failure during check → TempError
// ---------------------------------------------------------------------------

func TestDNSSettings(t *testing.T) {
	failResolver := errResolver(newDNSError("connection refused"))
	if got := spf.CheckHostWithResolver(ctx, net.ParseIP("87.237.204.223"), "example.com", "sender@example.com", "", failResolver); got != spf.TempError {
		t.Error("Failing DNS resolver should return TEMPERROR, got:", got)
	}
}

// ---------------------------------------------------------------------------
// TestCheckHost — table-driven, covers original integration scenarios
// ---------------------------------------------------------------------------

type testData struct {
	ip     net.IP
	domain string
	sender string
	helo   string
	result spf.Result
}

func newTestData(ip, domain, sender, helo string, expResult spf.Result) testData {
	return testData{
		ip:     net.ParseIP(ip),
		domain: domain,
		sender: sender,
		helo:   helo,
		result: expResult,
	}
}

func TestCheckHost(t *testing.T) {
	ip := "188.93.126.226"
	ip2 := "87.237.205.46"

	data := []testData{
		newTestData(ip, "example.com", "sender@example.com", "", spf.Pass),
		newTestData(ip, "mail.example.com", "sender@mail.example.com", "", spf.Pass),
		newTestData(ip, "smtp.example.com", "sender@smtp.example.com", "", spf.Pass),
		newTestData(ip, "gmail.com", "user@gmail.com", "", spf.Softfail),
		newTestData(ip, "hotmail.com", "user@hotmail.com", "", spf.Softfail),
		newTestData(ip2, "smtp.example.com", "sender@smtp.example.com", "", spf.Pass),
		newTestData(ip2, "outbound.example.com", "sender@outbound.example.com", "", spf.Pass),
	}

	resolver := newMockResolver()
	for _, d := range data {
		if got := spf.CheckHostWithResolver(ctx, d.ip, d.domain, d.sender, d.helo, resolver); got != d.result {
			t.Error("CheckHost", d.ip, d.domain, d.sender, "should", d.result, "returned:", got)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCaseSensitivity — mechanisms and modifiers are case-insensitive
// ---------------------------------------------------------------------------

func TestCaseInsensitiveMechanisms(t *testing.T) {
	cases := []testCase{
		{
			name: "uppercase IP4", ip: "1.2.3.4", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 IP4:1.2.3.4 -all"}}),
		},
		{
			name: "mixed case All", ip: "1.2.3.4", domain: "d.example", sender: "u@d.example", want: spf.Softfail,
			r: resolverWith(map[string][]string{"d.example": {"v=spf1 ~All"}}),
		},
		{
			name: "uppercase V=SPF1", ip: "1.2.3.4", domain: "d.example", sender: "u@d.example", want: spf.Pass,
			r: resolverWith(map[string][]string{"d.example": {"V=SPF1 ip4:1.2.3.4 -all"}}),
		},
	}
	runCases(t, cases)
}

// ---------------------------------------------------------------------------
// TestMacro — RFC §7.2 macro expansion (no DNS)
// ---------------------------------------------------------------------------

func TestMacro(t *testing.T) {
	sender := "strong-bad@email.example.com"
	ip := net.ParseIP("192.0.2.3")

	test := map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}":  "3.2.0.192.in-addr.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
	}

	for m, r := range test {
		res := spf.Macro(m, ip, "email.example.com", sender, "hello.server")
		if res != r {
			t.Fatal(m, "result should be", r, "returned:", res)
		}
	}
}

// TestMacroSenderLocalPartWithAt: a quoted local part may hold '@' (RFC 5321
// §4.1.2), so the sender's domain is what follows the LAST '@'. %{l} and %{o}
// (RFC 7208 §7.3) must split there; %{d} is the current domain, not the
// sender's, and %{s} is the whole sender.
func TestMacroSenderLocalPartWithAt(t *testing.T) {
	ip := net.ParseIP("192.0.2.3")
	cases := []struct {
		sender, macro, want string
	}{
		{`"a@b"@email.example.com`, "%{l}", `"a@b"`},
		{`"a@b"@email.example.com`, "%{o}", "email.example.com"},
		{`"a@b"@email.example.com`, "%{o2}", "example.com"},
		{`"a@b"@email.example.com`, "%{or}", "com.example.email"},
		{`"a@b"@email.example.com`, "%{s}", `"a@b"@email.example.com`},
		{`"a@b"@email.example.com`, "%{d}", "email.example.com"},
		// The same local part as a decoder hands it over, quotes removed.
		{"a@b@email.example.com", "%{l}", "a@b"},
		{"a@b@email.example.com", "%{o}", "email.example.com"},
		{"strong-bad@email.example.com", "%{l}", "strong-bad"},
		{"strong-bad@email.example.com", "%{o}", "email.example.com"},
	}
	for _, tc := range cases {
		got := spf.Macro(tc.macro, ip, "email.example.com", tc.sender, "hello.server")
		if got != tc.want {
			t.Errorf("Macro(%q) with sender %q: got %q, want %q", tc.macro, tc.sender, got, tc.want)
		}
	}
}

func TestMacroSpecialEscapes(t *testing.T) {
	ip := net.ParseIP("192.0.2.3")
	cases := []struct {
		in   string
		want string
	}{
		{"%%", "%"},
		{"%_", " "},
		{"%-", "%20"},
		{"hello%%world", "hello%world"},
	}
	for _, tc := range cases {
		got := spf.Macro(tc.in, ip, "example.com", "u@example.com", "")
		if got != tc.want {
			t.Errorf("Macro(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMacroHELO(t *testing.T) {
	ip := net.ParseIP("192.0.2.3")
	got := spf.Macro("%{h}", ip, "example.com", "u@example.com", "helo.server")
	if got != "helo.server" {
		t.Errorf("%%{h}: got %q, want %q", got, "helo.server")
	}
}

func TestMacroIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if got := spf.Macro("%{v}", ip, "example.com", "u@example.com", ""); got != "ip6" {
		t.Errorf("%%{v} for IPv6: got %q, want %q", got, "ip6")
	}
	// RFC 7208 §7.3: "dot-format", the 32 nibbles, not the colon form.
	want := "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
	if got := spf.Macro("%{i}", ip, "example.com", "u@example.com", ""); got != want {
		t.Errorf("%%{i} for IPv6: got %q, want %q", got, want)
	}
}

func TestMacroP(t *testing.T) {
	orig := spf.DefaultResolver
	defer func() { spf.DefaultResolver = orig }()

	ip := net.ParseIP("1.2.3.4")

	// Case 1: Validated domain
	r := resolverFull(
		nil, nil,
		map[string][]string{"mail.example.com": {"1.2.3.4"}},
		nil,
		map[string][]string{"1.2.3.4": {"mail.example.com"}},
	)
	spf.DefaultResolver = r

	got := spf.Macro("%{p}", ip, "example.com", "u@example.com", "")
	if got != "mail.example.com" {
		t.Errorf("%%{p} validated: got %q, want %q", got, "mail.example.com")
	}

	// Case 2: Unvalidated domain (PTR exists but A doesn't match)
	r = resolverFull(
		nil, nil,
		map[string][]string{"mail.example.com": {"5.6.7.8"}},
		nil,
		map[string][]string{"1.2.3.4": {"mail.example.com"}},
	)
	spf.DefaultResolver = r

	got = spf.Macro("%{p}", ip, "example.com", "u@example.com", "")
	if got != "unknown" {
		t.Errorf("%%{p} unvalidated: got %q, want %q", got, "unknown")
	}

	// Case 3: No PTR record
	r = resolverFull(nil, nil, nil, nil, nil)
	spf.DefaultResolver = r

	got = spf.Macro("%{p}", ip, "example.com", "u@example.com", "")
	if got != "unknown" {
		t.Errorf("%%{p} no PTR: got %q, want %q", got, "unknown")
	}
}

// TestExpModifier verifies that the "exp" modifier is processed on Fail.
func TestExpModifier(t *testing.T) {
	// Case 1: Fail with exp
	r := resolverWith(map[string][]string{
		"domain.com":  {"v=spf1 -all exp=explain.com"},
		"explain.com": {"%{d} says no"},
	})

	ip := net.ParseIP("1.2.3.4")
	res, exp := spf.CheckHostWithExplanationAndResolver(ctx, ip, "domain.com", "sender@domain.com", "", r)
	if res != spf.Fail {
		t.Errorf("expected Fail, got %s", res)
	}
	if exp != "domain.com says no" {
		t.Errorf("expected explanation 'domain.com says no', got %q", exp)
	}

	// Case 2: Pass with exp (exp ignored)
	r = resolverWith(map[string][]string{
		"domain.com":  {"v=spf1 +all exp=explain.com"},
		"explain.com": {"%{d} says no"},
	})

	res, exp = spf.CheckHostWithExplanationAndResolver(ctx, ip, "domain.com", "sender@domain.com", "", r)
	if res != spf.Pass {
		t.Errorf("expected Pass, got %s", res)
	}
	if exp != "" {
		t.Errorf("expected empty explanation on Pass, got %q", exp)
	}

	// Case 3: Redirect ignores this policy's exp (RFC 7208 section 6.2).
	r = resolverWith(map[string][]string{
		"domain.com":  {"v=spf1 redirect=other.com exp=explain.com"},
		"other.com":   {"v=spf1 -all"},
		"explain.com": {"Redirected fail"},
	})

	res, exp = spf.CheckHostWithExplanationAndResolver(ctx, ip, "domain.com", "sender@domain.com", "", r)
	if res != spf.Fail {
		t.Errorf("expected Fail from redirect, got %s", res)
	}
	if exp != "" {
		t.Errorf("expected no explanation from the original policy after redirect, got %q", exp)
	}
}

// TestSenderLocalPartWithAt runs %{o} and %{l} through check_host() with a
// local part that holds '@'. Through an include, %{o} still names the
// original sender's domain, so the exists name must be built from the domain
// after the LAST '@' (only that name has an A record); the explanation of a
// failing record shows what %{l} and %{o} expanded to.
func TestSenderLocalPartWithAt(t *testing.T) {
	passing := resolverFull(
		map[string][]string{
			"example.com":      {"v=spf1 include:_spf.esp.example -all"},
			"_spf.esp.example": {"v=spf1 exists:%{o}._senders.esp.example -all"},
		},
		nil,
		map[string][]string{"example.com._senders.esp.example": {"127.0.0.2"}},
		nil, nil,
	)
	failing := resolverWith(map[string][]string{
		"example.com":         {"v=spf1 -all exp=explain.example.com"},
		"explain.example.com": {"%{l} may not send for %{o}"},
	})
	cases := []struct {
		sender, local string
	}{
		{`"a@b"@example.com`, `"a@b"`},
		// The same local part as a decoder hands it over, quotes removed.
		{"a@b@example.com", "a@b"},
		{"u@example.com", "u"},
	}
	ip := net.ParseIP("192.0.2.3")
	for _, tc := range cases {
		t.Run(tc.sender, func(t *testing.T) {
			if got := spf.CheckHostWithResolver(ctx, ip, "example.com", tc.sender, "", passing); got != spf.Pass {
				t.Errorf("exists:%%{o}._senders.esp.example: got %s, want %s", got, spf.Pass)
			}
			res, exp := spf.CheckHostWithExplanationAndResolver(ctx, ip, "example.com", tc.sender, "", failing)
			if res != spf.Fail {
				t.Fatalf("-all: got %s, want %s", res, spf.Fail)
			}
			if want := tc.local + " may not send for example.com"; exp != want {
				t.Errorf("explanation: got %q, want %q", exp, want)
			}
		})
	}
}

// unqueryableSenders hold local parts that are legal in an address (atext,
// RFC 5322 §3.2.3; up to 64 octets, RFC 5321 §4.5.3.1.1) but that no DNS
// query can carry once %{l} puts them in a label: IDNA's Lookup profile
// refuses the plus sign, the apostrophe and the exclamation mark, and a label
// is at most 63 octets.
var unqueryableSenders = []string{
	"user+tag@example.com",
	"o'brien@example.com",
	"a!b@example.com",
	strings.Repeat("a", 64) + "@example.com",
}

// TestUnqueryableExpandedName: a macro-expanded target name that cannot be
// queried names nothing, so the mechanism does not match and evaluation goes
// on, as for a name that does not exist (Open-Email/smtp-in#129). One
// sender's local part must not turn the whole record into a PermError.
func TestUnqueryableExpandedName(t *testing.T) {
	const client = "192.0.2.3"
	policy := func(record string) *mockResolver {
		return resolverFull(
			map[string][]string{"example.com": {record}},
			nil,
			map[string][]string{"user._spf.example.com": {"127.0.0.2"}},
			nil, nil,
		)
	}
	var cases []testCase
	for _, sender := range unqueryableSenders {
		for _, tc := range []struct {
			record string
			want   spf.Result
		}{
			{"v=spf1 exists:%{l}._spf.example.com -all", spf.Fail},
			{"v=spf1 exists:%{l}._spf.example.com ?all", spf.Neutral},
			{"v=spf1 exists:%{l}._spf.example.com ip4:" + client + " -all", spf.Pass},
			{"v=spf1 a:%{l}.example.com -all", spf.Fail},
			{"v=spf1 mx:%{l}.example.com -all", spf.Fail},
			{"v=spf1 ptr:%{l}.example.com -all", spf.Fail},
		} {
			cases = append(cases, testCase{
				name: sender + " " + tc.record, ip: client, domain: "example.com", sender: sender,
				want: tc.want, r: policy(tc.record),
			})
		}
	}
	runCases(t, cases)
}

// TestUnqueryableExpandedNameGuards pins what the change must leave alone:
// a queryable %{l} still matches, a record that splits the local part on '+'
// (RFC 7208 §7.4's %{l1r+-}) still works, and include/redirect to an
// unqueryable target behave as include/redirect to a name with no SPF record
// (RFC 7208 §5.2, §6.1: PermError).
func TestUnqueryableExpandedNameGuards(t *testing.T) {
	const client = "192.0.2.3"
	a := map[string][]string{"user._spf.example.com": {"127.0.0.2"}}
	txt := func(record string) map[string][]string {
		return map[string][]string{
			"example.com":           {record},
			"user._spf.example.com": {"v=spf1 ip4:" + client + " -all"},
		}
	}
	runCases(t, []testCase{
		{
			name: "plain local part still matches exists", ip: client, domain: "example.com", sender: "user@example.com", want: spf.Pass,
			r: resolverFull(txt("v=spf1 exists:%{l}._spf.example.com -all"), nil, a, nil, nil),
		},
		{
			name: "plus split by the record still matches", ip: client, domain: "example.com", sender: "user+tag@example.com", want: spf.Pass,
			r: resolverFull(txt("v=spf1 exists:%{l1r+-}._spf.example.com -all"), nil, a, nil, nil),
		},
		{
			name: "plain local part still matches include", ip: client, domain: "example.com", sender: "user@example.com", want: spf.Pass,
			r: resolverFull(txt("v=spf1 include:%{l}._spf.example.com -all"), nil, nil, nil, nil),
		},
		{
			name: "include to a name with no SPF record", ip: client, domain: "example.com", sender: "nobody@example.com", want: spf.PermError,
			r: resolverFull(txt("v=spf1 include:%{l}._spf.example.com -all"), nil, nil, nil, nil),
		},
		{
			name: "include to an unqueryable name", ip: client, domain: "example.com", sender: "user+tag@example.com", want: spf.PermError,
			r: resolverFull(txt("v=spf1 include:%{l}._spf.example.com -all"), nil, nil, nil, nil),
		},
		{
			name: "redirect to a name with no SPF record", ip: client, domain: "example.com", sender: "nobody@example.com", want: spf.PermError,
			r: resolverFull(txt("v=spf1 redirect=%{l}._spf.example.com"), nil, nil, nil, nil),
		},
		{
			name: "redirect to an unqueryable name", ip: client, domain: "example.com", sender: "user+tag@example.com", want: spf.PermError,
			r: resolverFull(txt("v=spf1 redirect=%{l}._spf.example.com"), nil, nil, nil, nil),
		},
	})
}

// TestUnqueryableExpandedNameLimits: an unqueryable name still costs what an
// NXDOMAIN costs (RFC 7208 §4.6.4): one DNS-querying term and one void lookup.
func TestUnqueryableExpandedNameLimits(t *testing.T) {
	const client = "192.0.2.3"
	const sender = "user+tag@example.com"
	// Nine a: terms whose names exist but do not cover the client, then one
	// that does: the eleventh DNS term when an exists: before them counts.
	hosts := map[string][]string{"h10.example.com": {client}}
	terms := ""
	for i := 1; i <= 9; i++ {
		hosts[fmt.Sprintf("h%d.example.com", i)] = []string{"198.51.100.1"}
		terms += fmt.Sprintf(" a:h%d.example.com", i)
	}
	terms += " a:h10.example.com"
	runCases(t, []testCase{
		{
			name: "two void lookups allowed", ip: client, domain: "example.com", sender: sender, want: spf.Pass,
			r: resolverWith(map[string][]string{
				"example.com": {"v=spf1 exists:%{l}.one.example.com exists:%{l}.two.example.com ip4:" + client + " -all"},
			}),
		},
		{
			name: "three void lookups permerror", ip: client, domain: "example.com", sender: sender, want: spf.PermError,
			r: resolverWith(map[string][]string{
				"example.com": {"v=spf1 exists:%{l}.one.example.com exists:%{l}.two.example.com exists:%{l}.three.example.com ip4:" + client + " -all"},
			}),
		},
		{
			name: "ten DNS terms pass", ip: client, domain: "example.com", sender: sender, want: spf.Pass,
			r: resolverFull(map[string][]string{"example.com": {"v=spf1" + terms + " -all"}}, nil, hosts, nil, nil),
		},
		{
			name: "the unqueryable exists makes the last a: the eleventh DNS term", ip: client, domain: "example.com", sender: sender, want: spf.PermError,
			r: resolverFull(map[string][]string{"example.com": {"v=spf1 exists:%{l}._spf.example.com" + terms + " -all"}}, nil, hosts, nil, nil),
		},
	})
}

// TestMalformedRecordNameStaysPermError: a name the RECORD spells wrong is
// the publisher's error, not the sender's, and stays a PermError (RFC 7208
// §4.6), also when a macro sits beside the malformed text. An unknown macro
// letter is a syntax error (RFC 7208 §7.1), a PermError of its own.
func TestMalformedRecordNameStaysPermError(t *testing.T) {
	for _, record := range []string{
		"v=spf1 exists:bad+label.example.com -all",
		"v=spf1 exists:bad+label.%{d} -all",
		"v=spf1 a:bad+label.example.com -all",
		"v=spf1 include:bad+label.example.com -all",
		"v=spf1 redirect=bad+label.%{d}",
		"v=spf1 exists:%{z}.example.com -all",
	} {
		r := resolverWith(map[string][]string{"example.com": {record}})
		if got := spf.CheckHostWithResolver(ctx, net.ParseIP("192.0.2.3"), "example.com", "user@example.com", "", r); got != spf.PermError {
			t.Errorf("%s: got %s, want %s", record, got, spf.PermError)
		}
	}
}

// TestLookupSPFUnqueryableName: a name no DNS query can carry has no SPF
// record (RFC 7208 §4.3: a malformed domain is None). Retrying cannot help,
// so it is not a TempError.
func TestLookupSPFUnqueryableName(t *testing.T) {
	orig := spf.DefaultResolver
	defer func() { spf.DefaultResolver = orig }()
	spf.DefaultResolver = resolverWith(map[string][]string{})
	if _, got := spf.LookupSPF(ctx, "user+tag.example.com"); got != spf.None {
		t.Errorf("got %s, want %s", got, spf.None)
	}
}

// TestContextCancellation verifies that a cancelled context propagates correctly.
func TestContextCancellation(t *testing.T) {
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// With a cancelled context and a real-ish resolver that would block,
	// we verify the library respects context. Using errResolver simulates this:
	// a resolver that always errors (like a cancelled context would cause).
	failResolver := errResolver(cancelCtx.Err())
	got := spf.CheckHostWithResolver(cancelCtx, net.ParseIP("1.2.3.4"), "example.com", "u@example.com", "", failResolver)
	if got != spf.TempError {
		t.Errorf("cancelled context: want TempError, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkCheckHostIP4Pass(b *testing.B) {
	r := resolverWith(map[string][]string{
		"bench.example": {"v=spf1 ip4:1.2.3.0/24 -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	for b.Loop() {
		spf.CheckHostWithResolver(ctx, ip, "bench.example", "u@bench.example", "", r)
	}
}

func BenchmarkCheckHostInclude(b *testing.B) {
	r := resolverWith(map[string][]string{
		"bench.example": {"v=spf1 include:inner.example -all"},
		"inner.example": {"v=spf1 ip4:1.2.3.0/24 -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	for b.Loop() {
		spf.CheckHostWithResolver(ctx, ip, "bench.example", "u@bench.example", "", r)
	}
}

func BenchmarkCheckHostRedirect(b *testing.B) {
	r := resolverWith(map[string][]string{
		"bench.example":  {"v=spf1 redirect=target.example"},
		"target.example": {"v=spf1 ip4:1.2.3.0/24 -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	for b.Loop() {
		spf.CheckHostWithResolver(ctx, ip, "bench.example", "u@bench.example", "", r)
	}
}

func BenchmarkCheckHostManyIP4(b *testing.B) {
	spfRecord := "v=spf1"
	for i := 1; i < 50; i++ {
		spfRecord += fmt.Sprintf(" ip4:10.0.%d.0/24", i)
	}
	spfRecord += " -all"

	r := resolverWith(map[string][]string{
		"bench.example": {spfRecord},
	})
	ip := net.ParseIP("10.0.25.1")
	for b.Loop() {
		spf.CheckHostWithResolver(ctx, ip, "bench.example", "u@bench.example", "", r)
	}
}

func BenchmarkMacroExpansion(b *testing.B) {
	ip := net.ParseIP("192.0.2.3")
	for b.Loop() {
		spf.Macro("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", ip, "email.example.com", "strong-bad@email.example.com", "hello.server")
	}
}
