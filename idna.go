package spf

import (
	"context"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"strings"
)

// DNS mechanism names may have ASCII service labels such as _spf. Convert
// internationalized labels with Lookup while retaining those service labels.
func canonicalDNSName(name string) (string, error) {
	name = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		if label == "" {
			return "", fmt.Errorf("empty DNS label")
		}
		if strings.Contains(label, "_") {
			for _, r := range label {
				if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
					return "", fmt.Errorf("invalid service label")
				}
			}
			labels[i] = strings.ToLower(label)
		} else {
			ascii, err := idna.Lookup.ToASCII(label)
			if err != nil {
				return "", err
			}
			labels[i] = strings.ToLower(ascii)
		}
		if len(labels[i]) == 0 || len(labels[i]) > 63 || strings.Contains(labels[i], ".") {
			return "", fmt.Errorf("invalid DNS label")
		}
	}
	result := strings.Join(labels, ".")
	if len(result) > 253 {
		return "", fmt.Errorf("DNS name too long")
	}
	return result, nil
}

type idnaResolver struct{ Resolver }

func (r idnaResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupTXT(ctx, name)
}
func (r idnaResolver) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupA(ctx, name)
}
func (r idnaResolver) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupAAAA(ctx, name)
}
func (r idnaResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	name, err := canonicalDNSName(name)
	if err != nil {
		return nil, err
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

func (c *check) domainSpec(spec string, ip net.IP, domain, sender string) (string, Result) {
	expanded, result := c.macro(spec, ip, domain, sender, c.helo)
	if result != None {
		return "", result
	}
	name, err := canonicalDNSName(expanded)
	if err != nil {
		return "", PermError
	}
	return name, None
}
