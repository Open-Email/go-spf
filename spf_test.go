package spf_test

import (
	"context"
	"fmt"
	"net"
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
	r := resolverWith(map[string][]string{
		"v0.example": {"v=spf1 redirect=v1.example"},
		"v1.example": {"not-an-spf-record"},
		"v2.example": {"also-not-spf"},
		"v3.example": {"v=spf1 ip4:1.2.3.4 -all"},
	})
	ip := net.ParseIP("1.2.3.4")
	got := spf.CheckHostWithResolver(ctx, ip, "v0.example", "u@v0.example", "", r)
	if got != spf.None {
		t.Errorf("void lookup (single): want None, got %s", got)
	}
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
	if got := spf.Macro("%{i}", ip, "example.com", "u@example.com", ""); got != ip.String() {
		t.Errorf("%%{i} for IPv6: got %q, want %q", got, ip.String())
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

	// Case 3: Redirect to Fail with exp
	r = resolverWith(map[string][]string{
		"domain.com":  {"v=spf1 redirect=other.com exp=explain.com"},
		"other.com":   {"v=spf1 -all"},
		"explain.com": {"Redirected fail"},
	})

	res, exp = spf.CheckHostWithExplanationAndResolver(ctx, ip, "domain.com", "sender@domain.com", "", r)
	if res != spf.Fail {
		t.Errorf("expected Fail from redirect, got %s", res)
	}
	if exp != "Redirected fail" {
		t.Errorf("expected explanation 'Redirected fail', got %q", exp)
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
