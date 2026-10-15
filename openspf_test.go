package spf_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Open-Email/go-spf"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// TestOpenSPF runs all 203 cases of the openspf.org RFC 7208 suite, release
// 2014.04, as shipped by sdgathman/pyspf at
// 1042e9e15dd29047dc9b0a1bb77437e2fd81e775. The unmodified YAML and its
// redistribution license live in testdata. No test makes a network query.
//
// Deliberate deviations retained from go-spf #4: a-colon-domain and its
// IPv4-mapped variant, mx-colon-domain and its IPv4-mapped variant, and
// macro-mania-in-domain use literal ':', '/', '%' or spaces in DNS labels.
// The library's IDNA Lookup profile refuses these record-authored labels,
// returning PermError. Each case still runs and asserts that policy, rather
// than being skipped. Sender-expanded unqueryable names remain non-matches.
// v-macro-ip6's explanation spells the IPv6 nibbles in uppercase; go-spf
// uses lowercase, as RFC 7208 section 7.4 does. Only that explanation's
// case is normalized; its result and all other explanations are exact.
func TestOpenSPF(t *testing.T) {
	f, err := os.Open("testdata/rfc7208-tests.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	count := 0
	for {
		var scenario openSPFScenario
		if err := decoder.Decode(&scenario); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		r := newOpenSPFResolver(t, scenario.ZoneData)
		names := make([]string, 0, len(scenario.Tests))
		for name := range scenario.Tests {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			tc := scenario.Tests[name]
			count++
			t.Run(scenario.Description+"/"+name, func(t *testing.T) {
				ip := net.ParseIP(tc.Host)
				if ip == nil {
					t.Fatalf("invalid fixture IP %q", tc.Host)
				}
				domain := tc.Helo
				if at := strings.LastIndexByte(tc.MailFrom, '@'); at >= 0 {
					domain = tc.MailFrom[at+1:]
				}
				got, explanation := spf.CheckHostWithExplanationAndResolver(context.Background(), ip, domain, tc.MailFrom, tc.Helo, r)
				var wants []string
				if tc.Result.Kind == yaml.SequenceNode {
					err = tc.Result.Decode(&wants)
				} else {
					var want string
					err = tc.Result.Decode(&want)
					wants = []string{want}
				}
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "a-colon-domain", "a-colon-domain-ip4mapped", "mx-colon-domain", "mx-colon-domain-ip4mapped", "macro-mania-in-domain":
					if len(wants) != 1 || wants[0] != "pass" {
						t.Fatalf("upstream expectation changed; review the documented IDNA deviation: %v", wants)
					}
					wants = []string{"permerror"}
					t.Log("documented IDNA policy deviation: literal non-IDNA DNS label")
				}
				matched := false
				for _, want := range wants {
					matched = matched || strings.EqualFold(got.String(), want)
				}
				if !matched {
					t.Errorf("result = %s, want %v (RFC %s; %s)", got, wants, tc.Spec, tc.Description)
				}
				if tc.Explanation != "" {
					want := tc.Explanation
					// DEFAULT means no publisher-provided explanation. The
					// library returns an empty string for caller policy to fill.
					if want == "DEFAULT" {
						want = ""
					}
					if name == "v-macro-ip6" {
						want = strings.ToLower(want)
					}
					if explanation != want {
						t.Errorf("explanation = %q, want %q", explanation, want)
					}
				}
			})
		}
	}
	if count != 203 {
		t.Fatalf("ran %d upstream cases, want 203", count)
	}
}

type openSPFScenario struct {
	Description string
	Tests       map[string]struct {
		Description string
		Spec        string
		Helo        string
		Host        string
		MailFrom    string `yaml:"mailfrom"`
		Result      yaml.Node
		Explanation string
	}
	ZoneData map[string][]yaml.Node `yaml:"zonedata"`
}

type openSPFResolver struct {
	records map[string]map[string][]string
	timeout map[string]bool
}

// The upstream driver duplicates SPF into TXT only when TXT is absent.
// An explicit TXT: NONE suppresses duplication. A TIMEOUT beside an actual
// TXT answer applies to the obsolete type-SPF query, which we never make.
func newOpenSPFResolver(t *testing.T, zone map[string][]yaml.Node) *openSPFResolver {
	t.Helper()
	r := &openSPFResolver{records: make(map[string]map[string][]string), timeout: make(map[string]bool)}
	for name, entries := range zone {
		name = comparableSuiteName(name)
		records := make(map[string][]string)
		for _, entry := range entries {
			if entry.Kind == yaml.ScalarNode {
				if entry.Value != "TIMEOUT" {
					t.Fatalf("unknown zone marker %q", entry.Value)
				}
				r.timeout[name] = true
				continue
			}
			if entry.Kind != yaml.MappingNode || len(entry.Content) != 2 {
				t.Fatalf("invalid record at %s", name)
			}
			kind, value := entry.Content[0].Value, entry.Content[1]
			var data string
			if value.Kind == yaml.SequenceNode {
				var pieces []string
				if err := value.Decode(&pieces); err != nil {
					t.Fatal(err)
				}
				if kind == "MX" {
					if len(pieces) != 2 {
						t.Fatalf("invalid MX at %s", name)
					}
					data = pieces[1] // preference is not part of the hostname
				} else {
					data = strings.Join(pieces, "")
				}
			} else if err := value.Decode(&data); err != nil {
				t.Fatal(err)
			}
			if data == "NONE" {
				records[kind] = nil
			} else {
				records[kind] = append(records[kind], data)
			}
		}
		if _, explicitTXT := records["TXT"]; !explicitTXT {
			records["TXT"] = records["SPF"]
		}
		r.records[name] = records
	}
	return r
}

func comparableSuiteName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (r *openSPFResolver) lookup(ctx context.Context, name, kind string) ([]string, error) {
	seen := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name = comparableSuiteName(name)
		if seen[name] || len(seen) > 10 {
			return nil, fmt.Errorf("CNAME loop at %s", name)
		}
		seen[name] = true
		records := r.records[name]
		if r.timeout[name] && (kind != "TXT" || len(records["TXT"]) == 0) {
			return nil, &net.DNSError{Err: "fixture timeout", Name: name, IsTimeout: true}
		}
		if len(records["CNAME"]) == 0 {
			return records[kind], nil
		}
		name = records["CNAME"][0]
	}
}

func (r *openSPFResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.lookup(ctx, name, "TXT")
}

func (r *openSPFResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	return r.lookup(ctx, name, "MX")
}

func (r *openSPFResolver) addresses(ctx context.Context, name, kind string) ([]net.IP, error) {
	values, err := r.lookup(ctx, name, kind)
	var ips []net.IP
	for _, value := range values {
		ips = append(ips, net.ParseIP(value))
	}
	return ips, err
}

func (r *openSPFResolver) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	return r.addresses(ctx, name, "A")
}

func (r *openSPFResolver) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	return r.addresses(ctx, name, "AAAA")
}

func (r *openSPFResolver) LookupPTR(ctx context.Context, ip net.IP) ([]string, error) {
	name, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return nil, err
	}
	return r.lookup(ctx, name, "PTR")
}
