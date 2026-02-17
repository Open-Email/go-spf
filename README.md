# spf

A Go library for checking [Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208) records, implementing RFC 7208.

Based on [mileusna/spf](https://github.com/mileusna/spf).

## Installation

```bash
go get github.com/migadu/spf
```

## Usage

### Basic check

```go
import (
    "context"
    "net"
    "github.com/migadu/spf"
)

ctx := context.Background()
ip := net.ParseIP("203.0.113.1")
result := spf.CheckHost(ctx, ip, "example.com", "sender@example.com", "mail.example.com")

switch result {
case spf.Pass:
    // sender is authorized
case spf.Fail:
    // sender is not authorized
case spf.Softfail:
    // sender is not authorized, but domain is not explicitly rejecting
case spf.Neutral:
    // domain makes no assertion
case spf.None:
    // no SPF record found
case spf.TempError:
    // transient DNS error, try again later
case spf.PermError:
    // permanent error (e.g. malformed SPF record)
}
```

### With explanation string

When the result is `Fail`, the domain's `exp=` modifier (if present) provides a human-readable explanation:

```go
result, explanation := spf.CheckHostWithExplanation(ctx, ip, "example.com", "sender@example.com", "mail.example.com")
if result == spf.Fail && explanation != "" {
    log.Println("SPF fail reason:", explanation)
}
```

### Custom DNS resolver

Change the DNS server used by the default resolver:

```go
spf.DNSServer = "1.1.1.1:53" // default: 8.8.8.8:53
```

Configure the DNS query timeout:

```go
spf.DNSTimeout = 5 * time.Second // default: 2s
```

Or implement the `Resolver` interface for full control (custom resolver, caching, mocking in tests):

```go
type Resolver interface {
    LookupTXT(ctx context.Context, domain string) ([]string, error)
    LookupMX(ctx context.Context, domain string) ([]string, error)
    LookupA(ctx context.Context, domain string) ([]net.IP, error)
    LookupAAAA(ctx context.Context, domain string) ([]net.IP, error)
    LookupPTR(ctx context.Context, ip net.IP) ([]string, error)
}

result := spf.CheckHostWithResolver(ctx, ip, "example.com", "sender@example.com", "", myResolver)
```

The `CheckHostWithExplanationAndResolver` variant combines both:

```go
result, explanation := spf.CheckHostWithExplanationAndResolver(ctx, ip, domain, sender, helo, myResolver)
```

### Fetching the raw SPF record

```go
record, result := spf.LookupSPF(ctx, "example.com")
// record: "v=spf1 ip4:203.0.113.0/24 ~all"
// result: None if no record, PermError if multiple records found
```

## API

| Function | Description |
|---|---|
| `CheckHost(ctx, ip, domain, sender, helo)` | Main SPF check, returns `Result` |
| `CheckHostWithExplanation(ctx, ip, domain, sender, helo)` | Returns `(Result, explanation)` |
| `CheckHostWithResolver(ctx, ip, domain, sender, helo, resolver)` | Check with custom `Resolver` |
| `CheckHostWithExplanationAndResolver(ctx, ip, domain, sender, helo, resolver)` | Custom resolver and explanation |
| `LookupSPF(ctx, domain)` | Fetch raw SPF TXT record |

**Parameters:**
- `ctx` — context for cancellation and timeouts
- `ip` — IP address of the connecting SMTP client
- `domain` — domain to check SPF for (from `MAIL FROM` or `HELO`)
- `sender` — full `MAIL FROM` address; if empty, `postmaster@<helo>` is used
- `helo` — domain from the SMTP `HELO`/`EHLO` command

## RFC 7208 compliance

Supported mechanisms: `all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6`, `exists`

Supported modifiers: `redirect=`, `exp=`

Supported macro letters: `s`, `l`, `o`, `d`, `i`, `p`, `v`, `h` with digit, `r` (reverse), and delimiter transformers

Enforced limits per RFC §4.6.4:
- 10 DNS-querying mechanisms per evaluation
- 2 void lookups (NXDOMAIN / empty responses)
- 10 MX or PTR records per mechanism
- 10 levels of `include`/`redirect` recursion
- 10 CNAME hops per DNS lookup

Additional features:
- Case-insensitive mechanism and modifier parsing
- Duplicate `redirect=` or `exp=` modifier detection (→ PermError)
- IPv6 PTR validation uses AAAA records (not A)
- DNS errors on `exists` mechanism correctly return TempError
- Void lookup counting on `exists` empty responses
- TCP fallback on DNS truncation
- Configurable DNS timeout via `DNSTimeout`
- Context support for cancellation and deadline propagation

## License

MIT
