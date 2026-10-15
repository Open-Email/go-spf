package spf

import (
	"context"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"strings"
)

// maxNameLength is the longest domain name in dotted form, without the
// trailing dot (RFC 7208 §7.3).
const maxNameLength = 253

// DNS mechanism names may have ASCII service labels such as _spf. Convert
// internationalized labels with Lookup while retaining those service labels.
func canonicalDNSName(name string) (string, error) {
	return convertName(name, false)
}

// queryName converts a macro-expanded name for a query. One longer than 253
// octets is not refused: "the left side is truncated to fit, by removing
// successive domain labels (and their following dots) until the total
// length does not exceed 253 characters" (RFC 7208 §7.3). Labels are
// measured converted, as the query carries them, and only the labels that
// remain have to be valid.
func queryName(name string) (string, error) {
	return convertName(name, true)
}

func convertName(name string, truncate bool) (string, error) {
	name = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	errs := make([]error, len(labels))
	length := -1
	for i, label := range labels {
		labels[i], errs[i] = canonicalLabel(label)
		length += len(labels[i]) + 1
	}
	first := 0
	for truncate && length > maxNameLength && first < len(labels)-1 {
		length -= len(labels[first]) + 1
		first++
	}
	for _, err := range errs[first:] {
		if err != nil {
			return "", err
		}
	}
	if length > maxNameLength {
		return "", fmt.Errorf("DNS name too long")
	}
	return strings.Join(labels[first:], "."), nil
}

// canonicalLabel converts one label. On error it returns the label as given,
// so that a name can still be measured.
func canonicalLabel(label string) (string, error) {
	if label == "" {
		return label, fmt.Errorf("empty DNS label")
	}
	var converted string
	if strings.Contains(label, "_") {
		for _, r := range label {
			if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return label, fmt.Errorf("invalid service label")
			}
		}
		converted = strings.ToLower(label)
	} else {
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return label, err
		}
		converted = strings.ToLower(ascii)
	}
	if len(converted) == 0 || len(converted) > 63 || strings.Contains(converted, ".") {
		return label, fmt.Errorf("invalid DNS label")
	}
	return converted, nil
}

// idnaResolver converts every name before the lookup. A name that cannot be
// converted cannot be put in a query, so no DNS data exists for it: it is
// answered as the NXDOMAIN path answers (no records, no error), and each
// mechanism takes it from there (a void lookup and no match; include and
// redirect find no record). In check_host only a macro-expanded name reaches
// here unconverted (see domainSpec); LookupSPF passes its argument as given.
type idnaResolver struct{ Resolver }

func (r idnaResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, nil
	}
	return r.Resolver.LookupTXT(ctx, name)
}
func (r idnaResolver) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, nil
	}
	return r.Resolver.LookupA(ctx, name)
}
func (r idnaResolver) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, nil
	}
	return r.Resolver.LookupAAAA(ctx, name)
}
func (r idnaResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, nil
	}
	hosts, err := r.Resolver.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	return canonicalHosts(hosts)
}
func (r idnaResolver) LookupPTR(ctx context.Context, ip net.IP) ([]string, error) {
	hosts, err := r.Resolver.LookupPTR(ctx, ip)
	if err != nil {
		return nil, err
	}
	return canonicalHosts(hosts)
}

// canonicalHosts converts MX and PTR answers. A null MX (RFC 7505 ".") and a
// name the Lookup profile refuses are skipped rather than fatal: one odd
// answer must not turn the whole mechanism into a TempError.
func canonicalHosts(hosts []string) ([]string, error) {
	result := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host == "" || host == "." {
			continue
		}
		name, err := canonicalDNSName(host)
		if err != nil {
			continue
		}
		result = append(result, name)
	}
	return result, nil
}

// domainSpec expands and converts a target name, truncated from the left to
// 253 octets (RFC 7208 §7.3). A name the record itself spells wrong is
// rejected up front by validDomainSpec (RFC 7208 §4.6). A name that only the
// expanded data made unqueryable (a local part such as "user+tag" or
// "o'brien", a label over 63 octets) names nothing: it is returned
// unconverted, so the lookup answers it as a name that does not exist and
// the mechanism does not match, counted as any other lookup and void lookup
// (Open-Email/smtp-in#129).
func (c *check) domainSpec(spec string, ip net.IP, domain, sender string) (string, Result) {
	expanded, result := c.macro(spec, ip, domain, sender, c.helo)
	if result != None {
		return "", result
	}
	name, err := queryName(expanded)
	if err == nil {
		return name, None
	}
	return expanded, None
}
