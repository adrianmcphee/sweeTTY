// Package safety holds structural guardrail tests that lock the honeypot's
// safety doctrine in place. The handler packages that touch attacker input must
// never gain the ability to fetch a URL, execute input, write the host disk, or
// read the host /proc. The package doc-comments assert this in prose; the tests
// here assert it in code, so a regression fails the build instead of silently
// turning the sensor into an open relay or a malware drop.
//
// Three layers, from narrowest to broadest:
//   - imports_test.go denies specific capability imports to each attacker-facing
//     handler by its DIRECT imports.
//   - closure_test.go walks the ENTIRE transitive dependency closure of the
//     honeypot binary and requires every internal package holding a capability
//     import to be explicitly approved, so a new helper package that quietly holds
//     os or net and is called from a handler cannot route around the direct scan.
//   - dialscan_test.go scans the syntax tree of the attacker-reachable packages for
//     an outbound dial or resolve call, closing the seam the import allowlist cannot
//     (portal legitimately imports net/http to serve the dashboard, so an outbound
//     http.Get there is caught by the call scan, not the import scan).
package safety
