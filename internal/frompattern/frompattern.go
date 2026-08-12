// Package frompattern implements the sender allow-list grammar.
//
// A pattern is "local@domain" in exactly one of four shapes:
//
//	no-reply@app.example.com    an exact address
//	*@example.com               any local part, that exact domain
//	no-reply@*.example.com      that local part, any subdomain
//	*@*.example.com             any local part, any subdomain
//
// Notably, "*.example.com" does not match "example.com" itself. Covering both
// takes two patterns, which is verbose on purpose: an operator granting a
// wildcard should have to say so twice rather than discover the extra reach
// afterwards.
//
// The grammar is closed and the matcher is pure string comparison. No pattern
// ever reaches a regular expression engine, so no operator input can cause
// catastrophic backtracking, and there is no way to express something the
// four shapes above do not cover.
package frompattern

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

const (
	wildcard = "*"
	// subdomainPrefix marks a domain pattern that matches strict subdomains.
	subdomainPrefix = "*."

	maxLocalLength   = 64
	maxDomainLength  = 253
	maxLabelLength   = 63
	maxPatternLength = 320
)

// ErrInvalidPattern reports a pattern outside the grammar. Admin writes must
// surface it to the operator; it is never returned on the mail path, because
// stored patterns are validated before insert and re-checked by a database
// constraint.
var ErrInvalidPattern = errors.New("invalid sender pattern")

// ErrInvalidAddress reports an address that cannot be normalized for matching.
var ErrInvalidAddress = errors.New("invalid sender address")

// Address is a normalized addr-spec, split and lowercased.
//
// The local part is compared case-insensitively. RFC 5321 permits case-sensitive
// local parts, but no mail system in practice relies on "Bob" and "bob" being
// different mailboxes, and treating them as distinct here would mean a pattern
// silently failing to cover an address an operator believes it covers.
type Address struct {
	Local  string
	Domain string
}

// String rebuilds the normalized address.
func (a Address) String() string {
	if a.Local == "" && a.Domain == "" {
		return ""
	}
	return a.Local + "@" + a.Domain
}

// IsZero reports whether the address is empty.
func (a Address) IsZero() bool { return a.Local == "" && a.Domain == "" }

// ParseAddress normalizes an addr-spec for matching.
//
// The input must already be a bare addr-spec: display names and angle brackets
// are the caller's problem (see internal/mailnorm), because deciding which
// address in a header is "the" sender is a separate concern from matching it.
func ParseAddress(raw string) (Address, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Address{}, fmt.Errorf("%w: empty address", ErrInvalidAddress)
	}
	if strings.ContainsAny(value, "<>") {
		return Address{}, fmt.Errorf("%w: expected a bare addr-spec, got angle brackets", ErrInvalidAddress)
	}

	// Splitting on the last '@' is what mail systems do: the domain cannot
	// contain '@', so anything before it belongs to the local part.
	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 {
		return Address{}, fmt.Errorf("%w: want local@domain", ErrInvalidAddress)
	}

	local, err := normalizeLocal(value[:at], ErrInvalidAddress)
	if err != nil {
		return Address{}, err
	}
	domain, err := normalizeDomain(value[at+1:], ErrInvalidAddress)
	if err != nil {
		return Address{}, err
	}
	return Address{Local: local, Domain: domain}, nil
}

// Pattern is a parsed, normalized sender pattern.
type Pattern struct {
	// normalized is the canonical text form, which is what gets stored.
	normalized string

	local    string
	localAny bool

	// domain never carries the "*." prefix; subdomainAny records it instead.
	domain       string
	subdomainAny bool
}

// Parse validates and normalizes a pattern.
func Parse(raw string) (Pattern, error) {
	value := strings.TrimSpace(raw)
	switch {
	case value == "":
		return Pattern{}, fmt.Errorf("%w: empty pattern", ErrInvalidPattern)
	case len(value) > maxPatternLength:
		return Pattern{}, fmt.Errorf("%w: longer than %d characters", ErrInvalidPattern, maxPatternLength)
	case strings.ContainsAny(value, "<> \t\r\n"):
		return Pattern{}, fmt.Errorf("%w: contains whitespace or angle brackets", ErrInvalidPattern)
	}

	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 {
		return Pattern{}, fmt.Errorf("%w: want local@domain", ErrInvalidPattern)
	}
	localPart, domainPart := value[:at], value[at+1:]

	p := Pattern{}

	if localPart == wildcard {
		p.localAny = true
		p.local = wildcard
	} else {
		if strings.Contains(localPart, wildcard) {
			// Rejecting "no-*@example.com" keeps matching to whole-token
			// comparison. Partial globs are where surprising over-matching
			// lives, and no real use case needs them.
			return Pattern{}, fmt.Errorf("%w: %q may only be the entire local part", ErrInvalidPattern, wildcard)
		}
		local, err := normalizeLocal(localPart, ErrInvalidPattern)
		if err != nil {
			return Pattern{}, err
		}
		p.local = local
	}

	if rest, ok := strings.CutPrefix(domainPart, subdomainPrefix); ok {
		p.subdomainAny = true
		domainPart = rest
	}
	if strings.Contains(domainPart, wildcard) {
		return Pattern{}, fmt.Errorf("%w: %q is only allowed as the leading domain label", ErrInvalidPattern, subdomainPrefix)
	}
	domain, err := normalizeDomain(domainPart, ErrInvalidPattern)
	if err != nil {
		return Pattern{}, err
	}
	p.domain = domain

	p.normalized = p.local + "@"
	if p.subdomainAny {
		p.normalized += subdomainPrefix
	}
	p.normalized += p.domain

	return p, nil
}

// MustParse is Parse for compile-time-known patterns in tests and fixtures.
func MustParse(raw string) Pattern {
	p, err := Parse(raw)
	if err != nil {
		panic(err)
	}
	return p
}

// String returns the canonical form, which is what is stored in the database.
func (p Pattern) String() string { return p.normalized }

// IsZero reports whether the pattern is the zero value.
func (p Pattern) IsZero() bool { return p.normalized == "" }

// Matches reports whether addr is authorized by this pattern.
//
// addr must come from ParseAddress: matching assumes both sides are already
// normalized, so this is plain equality and suffix comparison.
func (p Pattern) Matches(addr Address) bool {
	if p.IsZero() || addr.IsZero() {
		return false
	}
	if !p.localAny && p.local != addr.Local {
		return false
	}
	if p.subdomainAny {
		// A strict subdomain: the separating dot must be present, which is what
		// stops "*.example.com" from matching "notexample.com".
		return len(addr.Domain) > len(p.domain)+1 &&
			strings.HasSuffix(addr.Domain, "."+p.domain)
	}
	return addr.Domain == p.domain
}

// Set is a credential's compiled allow-list.
type Set struct {
	patterns []Pattern
}

// NewSet parses every pattern, rejecting the whole set if any one is invalid.
//
// Partial acceptance is not offered: silently dropping an unparsable pattern
// would quietly narrow (or, worse, widen) what a credential may send as.
func NewSet(raw []string) (Set, error) {
	set := Set{patterns: make([]Pattern, 0, len(raw))}
	seen := make(map[string]struct{}, len(raw))

	for i, item := range raw {
		p, err := Parse(item)
		if err != nil {
			return Set{}, fmt.Errorf("pattern %d (%q): %w", i+1, item, err)
		}
		if _, dup := seen[p.normalized]; dup {
			continue
		}
		seen[p.normalized] = struct{}{}
		set.patterns = append(set.patterns, p)
	}
	return set, nil
}

// Len reports how many distinct patterns the set holds.
func (s Set) Len() int { return len(s.patterns) }

// Patterns returns the parsed patterns, for display.
func (s Set) Patterns() []Pattern { return s.patterns }

// Match returns the first pattern authorizing addr.
//
// An empty set matches nothing. That is the single most important property in
// this package: a credential with no configured pattern can send as nobody,
// never as anybody.
func (s Set) Match(addr Address) (Pattern, bool) {
	for _, p := range s.patterns {
		if p.Matches(addr) {
			return p, true
		}
	}
	return Pattern{}, false
}

// Allows is Match without the matched pattern.
func (s Set) Allows(addr Address) bool {
	_, ok := s.Match(addr)
	return ok
}

// NormalizeDomain canonicalizes a domain name for storage and comparison:
// lowercase, punycode, no trailing root dot, at least two labels.
//
// Every domain that reaches the database goes through this, so comparing a
// sender's domain to a stored one is always plain byte equality.
func NormalizeDomain(raw string) (string, error) {
	return normalizeDomain(raw, ErrInvalidAddress)
}

func normalizeLocal(raw string, kind error) (string, error) {
	local := strings.TrimSpace(raw)
	switch {
	case local == "":
		return "", fmt.Errorf("%w: empty local part", kind)
	case len(local) > maxLocalLength:
		return "", fmt.Errorf("%w: local part longer than %d characters", kind, maxLocalLength)
	case strings.HasPrefix(local, `"`) || strings.HasSuffix(local, `"`):
		// Quoted local parts are legal RFC 5321 and unusable in practice. They
		// would also make normalization ambiguous, so they are refused outright.
		return "", fmt.Errorf("%w: quoted local parts are not supported", kind)
	case strings.HasPrefix(local, "."), strings.HasSuffix(local, "."), strings.Contains(local, ".."):
		return "", fmt.Errorf("%w: misplaced dot in local part", kind)
	}

	for _, r := range local {
		if !isAllowedLocalRune(r) {
			return "", fmt.Errorf("%w: local part contains %q", kind, r)
		}
	}
	return strings.ToLower(local), nil
}

// isAllowedLocalRune accepts the RFC 5322 atext set plus '.', and nothing else.
// Non-ASCII is refused: SMTPUTF8 is not supported downstream, so accepting a
// unicode local part here would only defer the failure to delivery time.
func isAllowedLocalRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", r):
		return true
	default:
		return false
	}
}

func normalizeDomain(raw string, kind error) (string, error) {
	domain := strings.TrimSpace(raw)
	domain = strings.TrimSuffix(domain, ".") // a trailing root dot is harmless noise
	if domain == "" {
		return "", fmt.Errorf("%w: empty domain", kind)
	}

	// idna.Lookup applies the strict profile: it rejects mixed scripts and
	// disallowed code points rather than silently mangling them, and converts a
	// unicode domain to its punycode form so comparison stays byte-wise.
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(domain))
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a usable domain: %v", kind, domain, err)
	}
	if len(ascii) > maxDomainLength {
		return "", fmt.Errorf("%w: domain longer than %d characters", kind, maxDomainLength)
	}

	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		// Requiring a dot rules out "localhost" and bare TLDs, neither of which
		// is a deliverable sender domain.
		return "", fmt.Errorf("%w: %q needs at least two labels", kind, ascii)
	}
	for _, label := range labels {
		if err := checkLabel(label, kind); err != nil {
			return "", err
		}
	}
	return ascii, nil
}

func checkLabel(label string, kind error) error {
	switch {
	case label == "":
		return fmt.Errorf("%w: empty domain label", kind)
	case len(label) > maxLabelLength:
		return fmt.Errorf("%w: domain label %q longer than %d characters", kind, label, maxLabelLength)
	case strings.HasPrefix(label, "-"), strings.HasSuffix(label, "-"):
		return fmt.Errorf("%w: domain label %q starts or ends with a hyphen", kind, label)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("%w: domain label %q contains %q", kind, label, r)
		}
	}
	return nil
}
