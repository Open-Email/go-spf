# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./...

# Run a single test
go test -run TestCheckHost

# Run tests with verbose output
go test -v ./...

# Run tests with race detector
go test -race ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Check test coverage
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# Update dependencies
go get -u ./...
go mod tidy
```

Tests use a `mockResolver` (in `mock_resolver_test.go`) for all DNS fixtures — no real network calls are needed. The mock is injected via the `CheckHostWithResolver` API.

## Architecture

Flat single-package Go library (`github.com/Open-Email/go-spf`) implementing SPF (Sender Policy Framework) per RFC 7208.

**Public API:**
- `CheckHost(ctx, ip, domain, sender, helo)` → `Result` — main entry point
- `CheckHostWithResolver(...)` — same but accepts a custom `Resolver`
- `CheckHostWithExplanation(...)` — also returns the `exp=` explanation string on Fail
- `CheckHostWithExplanationAndResolver(...)` — combination of the above two
- `LookupSPF(ctx, domain)` → `(string, Result)` — fetches the raw SPF TXT record via `DefaultResolver`
- `DNSServer` — package-level string (default `"8.8.8.8:53"`), controls the DNS server used by `DefaultResolver`
- `DNSTimeout` — package-level `time.Duration` (default `2s`), controls the DNS query timeout
- `DefaultResolver` — package-level `Resolver`; replace to inject a custom/mock resolver

All public functions accept `context.Context` as their first parameter for cancellation and timeout propagation.

**`Resolver` interface** (defined in [resolver.go](resolver.go)):
```go
type Resolver interface {
    LookupTXT(ctx context.Context, domain string) ([]string, error)
    LookupMX(ctx context.Context, domain string) ([]string, error)
    LookupA(ctx context.Context, domain string) ([]net.IP, error)
    LookupAAAA(ctx context.Context, domain string) ([]net.IP, error)
    LookupPTR(ctx context.Context, ip net.IP) ([]string, error)
}
```

**File responsibilities:**
- [spf.go](spf.go) — SPF record parsing (`parseSPF`), all mechanism/modifier evaluation (`checkHost`), the `check` struct tracking DNS lookup count and void lookup count (RFC limits: 10 DNS mechanisms, 2 void lookups, 10 recursion depth, 10 MX/PTR records)
- [resolver.go](resolver.go) — `dnsResolver` (default `Resolver` implementation via `github.com/miekg/dns`); CNAME following for A/AAAA/MX with depth cap; `LookupSPF` public function; `reverseIPArpa` for PTR lookups; TCP fallback on truncation
- [macro.go](macro.go) — RFC 7208 §7 macro expansion (`%{d}`, `%{i}`, `%{s}`, `%{h}`, etc.)
- [export_test.go](export_test.go) — package `spf` (white-box) test file; exports `ParseSPF`, `Macro`; contains `TestPTR` and `TestReverseIPArpa` using an `internalMockResolver`
- [mock_resolver_test.go](mock_resolver_test.go) — package `spf_test` (black-box); provides `mockResolver`, `newMockResolver()`, `errResolver()`, `resolverWith()`, `resolverFull()` helpers

**Evaluation flow:**
`CheckHost` → `check.checkHost` → `check.lookupSPF` (TXT lookup + SPF selection) → `parseSPF` (returns `[]interface{}` of `directive`/`modifier`) → per-mechanism handlers (`check`, `checkMX`, `checkPTR`) → `evalQualifier`. Modifiers (`redirect=`, `exp=`) are pre-scanned before directive evaluation.
