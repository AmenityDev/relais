package frompattern

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	valid := []struct {
		in         string
		wantLocal  string
		wantDomain string
	}{
		{"no-reply@example.com", "no-reply", "example.com"},
		{"No-Reply@Example.COM", "no-reply", "example.com"},
		{"  spaced@example.com  ", "spaced", "example.com"},
		{"first.last@mail.example.co.uk", "first.last", "mail.example.co.uk"},
		{"plus+tag@example.com", "plus+tag", "example.com"},
		{"trailing.root.dot@example.com.", "trailing.root.dot", "example.com"},
		// A unicode domain is normalized to punycode so that comparison stays a
		// byte-wise operation everywhere downstream.
		{"info@exemplé.com", "info", "xn--exempl-gva.com"},
	}
	for _, tc := range valid {
		got, err := ParseAddress(tc.in)
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", tc.in, err)
		}
		if got.Local != tc.wantLocal || got.Domain != tc.wantDomain {
			t.Fatalf("ParseAddress(%q) = %+v, want {%s %s}", tc.in, got, tc.wantLocal, tc.wantDomain)
		}
	}

	invalid := []string{
		"",
		"   ",
		"no-at-sign",
		"@example.com",
		"local@",
		"local@localhost",             // single label is not deliverable
		"local@example",               //
		"<wrapped@example.com>",       // the caller must strip angle brackets
		"Name <name@example.com>",     //
		"two@at@example.com",          // '@' is not allowed in the local part
		`"quoted local"@example.com`,  // legal RFC, unsupported here
		".leading@example.com",        //
		"trailing.@example.com",       //
		"double..dot@example.com",     //
		"space in@example.com",        //
		"local@exa mple.com",          //
		"local@-example.com",          //
		"local@example-.com",          //
		"local@example..com",          //
		"unicode-local-é@example.com", // SMTPUTF8 is not supported downstream
		strings.Repeat("a", 65) + "@example.com",
		"local@" + strings.Repeat("a", 64) + ".com",
	}
	for _, in := range invalid {
		if got, err := ParseAddress(in); err == nil {
			t.Fatalf("ParseAddress(%q) = %+v, want error", in, got)
		} else if !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("ParseAddress(%q) = %v, want ErrInvalidAddress", in, err)
		}
	}
}

// TestMatching is the specification of the grammar. Every row is a documented
// promise about what a credential may and may not send as.
func TestMatching(t *testing.T) {
	tests := []struct {
		pattern string
		address string
		want    bool
		why     string
	}{
		// Exact address.
		{"no-reply@app.example.com", "no-reply@app.example.com", true, "exact match"},
		{"no-reply@app.example.com", "No-Reply@App.Example.COM", true, "matching is case-insensitive"},
		{"no-reply@app.example.com", "noreply@app.example.com", false, "different local part"},
		{"no-reply@app.example.com", "no-reply@example.com", false, "different domain"},
		{"no-reply@app.example.com", "no-reply@other.example.com", false, "different subdomain"},

		// Any local part, exact domain.
		{"*@example.com", "anything@example.com", true, "wildcard local part"},
		{"*@example.com", "a.b+c@example.com", true, "wildcard local part covers dotted and tagged"},
		{"*@example.com", "anything@mail.example.com", false, "a bare domain does not cover subdomains"},
		{"*@example.com", "anything@notexample.com", false, "suffix lookalike"},
		{"*@example.com", "anything@example.com.evil.test", false, "domain is a prefix of the address domain"},

		// Exact local part, any subdomain.
		{"no-reply@*.example.com", "no-reply@mail.example.com", true, "single-level subdomain"},
		{"no-reply@*.example.com", "no-reply@a.b.example.com", true, "multi-level subdomain"},
		{"no-reply@*.example.com", "no-reply@example.com", false, "the wildcard does not cover the apex"},
		{"no-reply@*.example.com", "other@mail.example.com", false, "local part still has to match"},
		{"no-reply@*.example.com", "no-reply@mail.notexample.com", false, "the separating dot is required"},
		{"no-reply@*.example.com", "no-reply@notexample.com", false, "suffix lookalike"},

		// Any local part, any subdomain.
		{"*@*.example.com", "anyone@mail.example.com", true, "both wildcards"},
		{"*@*.example.com", "anyone@a.b.c.example.com", true, "deep subdomain"},
		{"*@*.example.com", "anyone@example.com", false, "the apex needs its own pattern"},
		{"*@*.example.com", "anyone@example.com.evil.test", false, "the apex must be a suffix, not a prefix"},
		{"*@*.example.com", "anyone@xexample.com", false, "no dot boundary"},

		// Internationalized domains normalize on both sides before comparison.
		{"*@exemplé.com", "info@xn--exempl-gva.com", true, "pattern is punycoded on parse"},
		{"*@xn--exempl-gva.com", "info@exemplé.com", true, "address is punycoded on parse"},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+" vs "+tc.address, func(t *testing.T) {
			p, err := Parse(tc.pattern)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.pattern, err)
			}
			addr, err := ParseAddress(tc.address)
			if err != nil {
				t.Fatalf("ParseAddress(%q): %v", tc.address, err)
			}
			if got := p.Matches(addr); got != tc.want {
				t.Fatalf("%q matches %q = %v, want %v (%s)", tc.pattern, tc.address, got, tc.want, tc.why)
			}
		})
	}
}

func TestParseNormalizes(t *testing.T) {
	tests := map[string]string{
		"No-Reply@Example.COM": "no-reply@example.com",
		"  *@Example.com  ":    "*@example.com",
		"*@*.Example.com":      "*@*.example.com",
		"info@exemplé.com":     "info@xn--exempl-gva.com",
		"*@*.exemplé.com":      "*@*.xn--exempl-gva.com",
		"admin@example.com.":   "admin@example.com",
	}
	for in, want := range tests {
		p, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if p.String() != want {
			t.Fatalf("Parse(%q).String() = %q, want %q", in, p.String(), want)
		}
		// Normalization must be a fixed point, otherwise a stored pattern would
		// change shape every time it is read back and re-saved.
		again, err := Parse(p.String())
		if err != nil {
			t.Fatalf("re-parsing %q: %v", p.String(), err)
		}
		if again.String() != p.String() {
			t.Fatalf("normalization is not idempotent: %q then %q", p.String(), again.String())
		}
	}
}

func TestParseRejectsOutsideGrammar(t *testing.T) {
	invalid := []struct {
		pattern string
		why     string
	}{
		{"", "empty"},
		{"   ", "blank"},
		{"example.com", "no local part"},
		{"@example.com", "empty local part"},
		{"*@", "empty domain"},
		{"*", "no domain"},
		{"**@example.com", "partial wildcard in local part"},
		{"no-*@example.com", "partial wildcard in local part"},
		{"*reply@example.com", "partial wildcard in local part"},
		{"*@ex*mple.com", "wildcard inside the domain"},
		{"*@*.*.example.com", "only one leading wildcard label"},
		{"*@sub.*.example.com", "wildcard must lead the domain"},
		{"*@example.*", "wildcard TLD"},
		{"*@*", "wildcard everything"},
		{"*@*.com", "single-label apex behind a wildcard"},
		{"*@localhost", "single-label domain"},
		{"* @example.com", "whitespace"},
		{"<*@example.com>", "angle brackets"},
		{"a@b@example.com", "two at signs in the local part"},
		{`"quoted"@example.com`, "quoted local part"},
		{strings.Repeat("a", 400) + "@example.com", "over the length limit"},
	}
	for _, tc := range invalid {
		t.Run(tc.why, func(t *testing.T) {
			if got, err := Parse(tc.pattern); err == nil {
				t.Fatalf("Parse(%q) = %q, want error (%s)", tc.pattern, got, tc.why)
			} else if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("Parse(%q) = %v, want ErrInvalidPattern", tc.pattern, err)
			}
		})
	}
}

// The single most important property in the package: no patterns means no
// authority. A credential that has not been granted anything can send as nobody.
func TestEmptySetMatchesNothing(t *testing.T) {
	set, err := NewSet(nil)
	if err != nil {
		t.Fatalf("NewSet(nil): %v", err)
	}
	if set.Len() != 0 {
		t.Fatalf("Len = %d, want 0", set.Len())
	}
	for _, address := range []string{"anyone@example.com", "root@localhost.example.com", "a@b.c"} {
		addr, err := ParseAddress(address)
		if err != nil {
			continue
		}
		if set.Allows(addr) {
			t.Fatalf("an empty set authorized %q", address)
		}
	}
	// The zero values must be inert too, in case a Set or Pattern is ever used
	// before being populated.
	if (Set{}).Allows(Address{Local: "a", Domain: "b.com"}) {
		t.Fatal("the zero Set authorized an address")
	}
	if (Pattern{}).Matches(Address{Local: "a", Domain: "b.com"}) {
		t.Fatal("the zero Pattern matched an address")
	}
}

func TestSetMatchAndDeduplication(t *testing.T) {
	set, err := NewSet([]string{
		"no-reply@app.example.com",
		"*@billing.example.com",
		// Duplicates differing only by case and spacing collapse into one.
		"No-Reply@App.Example.com",
		"  no-reply@app.example.com  ",
	})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (got %v)", set.Len(), set.Patterns())
	}

	addr, err := ParseAddress("invoices@billing.example.com")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	matched, ok := set.Match(addr)
	if !ok {
		t.Fatal("Match found nothing for an authorized address")
	}
	if matched.String() != "*@billing.example.com" {
		t.Fatalf("matched %q, want %q", matched, "*@billing.example.com")
	}

	denied, err := ParseAddress("invoices@example.com")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if _, ok := set.Match(denied); ok {
		t.Fatal("Match authorized an address no pattern covers")
	}
}

// One bad pattern rejects the whole set: silently dropping it would change what
// a credential is allowed to do without anyone being told.
func TestNewSetRejectsWholeSetOnOneBadPattern(t *testing.T) {
	_, err := NewSet([]string{"valid@example.com", "not a pattern", "*@example.com"})
	if err == nil {
		t.Fatal("NewSet accepted a set containing an invalid pattern")
	}
	if !strings.Contains(err.Error(), "pattern 2") {
		t.Fatalf("error %q does not identify which pattern failed", err)
	}
}

// The database CHECK constraint in 00001_init.sql is a second line of defence
// against a pattern written by something other than this package. If the two
// ever disagree, a valid pattern becomes un-insertable, so they are pinned
// together here.
func TestNormalizedPatternsSatisfyTheDatabaseConstraint(t *testing.T) {
	// Kept byte-identical to credential_from_pattern_shape.
	const constraint = `^(\*|[^@[:space:]*]+)@(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`
	// Go's regexp uses the same POSIX class syntax, so the expression transfers
	// verbatim apart from needing no escaping changes.
	re := regexp.MustCompile(strings.ReplaceAll(constraint, "[:space:]", `\s`))

	accepted := []string{
		"no-reply@app.example.com",
		"*@example.com",
		"no-reply@*.example.com",
		"*@*.example.com",
		"first.last+tag@example.co.uk",
		"weird!#$%&'+-/=?^_`{|}~@example.com",
		"info@exemplé.com",
		"*@*.exemplé.com",
	}
	for _, raw := range accepted {
		p, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if !re.MatchString(p.String()) {
			t.Fatalf("Parse accepted %q -> %q, which the database CHECK would reject", raw, p.String())
		}
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "*", "@", "*@", "a@b.c", "*@example.com", "no-reply@*.example.com",
		"*@*.example.com", "*@*.*", "a@@b.com", "\x00@example.com",
		"a@" + strings.Repeat("b", 300) + ".com", "é@é.é", "*@xn--.com",
		"a@b.c.", "..@example.com", "*@*.*.*",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		p, err := Parse(raw)
		if err != nil {
			// A rejected pattern must never be usable.
			if !p.IsZero() {
				t.Fatalf("Parse(%q) failed but returned a non-zero pattern %q", raw, p)
			}
			return
		}

		// Anything accepted must survive a round trip unchanged, otherwise the
		// stored form and the matched form could diverge.
		again, err := Parse(p.String())
		if err != nil {
			t.Fatalf("Parse accepted %q -> %q, which then failed to re-parse: %v", raw, p, err)
		}
		if again.String() != p.String() {
			t.Fatalf("normalization is not a fixed point: %q -> %q -> %q", raw, p, again)
		}

		// An accepted pattern must never authorize an address outside its own
		// domain: this is the property that a wildcard bug would break.
		outside := Address{Local: "attacker", Domain: "attacker.test"}
		if p.Matches(outside) && p.domain != "attacker.test" && !strings.HasSuffix("attacker.test", "."+p.domain) {
			t.Fatalf("pattern %q authorized an unrelated address %q", p, outside)
		}
	})
}

func FuzzParseAddressAgainstWildcardPattern(f *testing.F) {
	// A single wildcard pattern is the widest grant the grammar can express for
	// one domain. No address outside that domain may ever match it.
	pattern := MustParse("*@*.example.com")

	for _, s := range []string{
		"a@example.com", "a@mail.example.com", "a@example.com.evil.test",
		"a@xexample.com", "a@.example.com", "a@..example.com",
		"a@" + strings.Repeat("s.", 60) + "example.com",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		addr, err := ParseAddress(raw)
		if err != nil {
			return
		}
		if !pattern.Matches(addr) {
			return
		}
		// Matched: the domain must be a strict subdomain of example.com.
		if !strings.HasSuffix(addr.Domain, ".example.com") || addr.Domain == ".example.com" {
			t.Fatalf("%q (domain %q) matched *@*.example.com", raw, addr.Domain)
		}
	})
}
