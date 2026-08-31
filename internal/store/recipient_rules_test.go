package store

import (
	"testing"

	"github.com/amenitydev/relais/internal/frompattern"
)

// The asymmetry with the sender allow-list is the whole point of RecipientRules,
// and it is the property most likely to be "tidied up" by someone who notices
// that frompattern.Set already has an Allows method. If this test ever goes red,
// the guardrail has inverted: either every restricted credential can mail
// anyone, or every unrestricted one can mail nobody.
func TestUnrestrictedRulesAllowEveryAddress(t *testing.T) {
	rules, err := NewRecipientRules(nil)
	if err != nil {
		t.Fatalf("NewRecipientRules: %v", err)
	}
	if rules.Restricted() {
		t.Fatal("an empty recipient allow-list reports itself as restricted")
	}

	for _, address := range []string{
		"dev@team.example",
		"someone@a-customer-who-must-not-be-mailed.test",
		"x@sub.deep.example.org",
	} {
		addr, err := frompattern.ParseAddress(address)
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", address, err)
		}
		if !rules.Allows(addr) {
			t.Fatalf("an unrestricted credential was refused %s", address)
		}
		// Allowed, but by no pattern: the two questions have different answers and
		// the admin API reports both, because "allowed" alone would present an
		// unrestricted credential as a locked-down one.
		if _, ok := rules.MatchedBy(addr); ok {
			t.Fatalf("MatchedBy named a pattern for %s in an empty allow-list", address)
		}
	}

	// The zero value is reachable from AuthCredential{}, so it has to behave the
	// same way as one built from an empty list.
	var zero RecipientRules
	addr, err := frompattern.ParseAddress("anyone@anywhere.test")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if zero.Restricted() || !zero.Allows(addr) {
		t.Fatal("the zero value of RecipientRules does not allow everything")
	}
}

func TestRestrictedRulesAllowOnlyMatches(t *testing.T) {
	rules, err := NewRecipientRules([]string{"*@team.example", "lead@partner.example"})
	if err != nil {
		t.Fatalf("NewRecipientRules: %v", err)
	}
	if !rules.Restricted() {
		t.Fatal("a non-empty recipient allow-list reports itself as unrestricted")
	}

	cases := []struct {
		address string
		allowed bool
		matched string
	}{
		{"dev@team.example", true, "*@team.example"},
		{"anyone@team.example", true, "*@team.example"},
		{"lead@partner.example", true, "lead@partner.example"},
		// Not the same person: the local part is part of the pattern.
		{"intern@partner.example", false, ""},
		// A strict subdomain is a different domain, exactly as on the sender side.
		{"dev@sub.team.example", false, ""},
		// The address this feature exists to refuse.
		{"customer@real-business.test", false, ""},
	}

	for _, c := range cases {
		addr, err := frompattern.ParseAddress(c.address)
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", c.address, err)
		}
		if got := rules.Allows(addr); got != c.allowed {
			t.Fatalf("Allows(%s) = %v, want %v", c.address, got, c.allowed)
		}
		matched, ok := rules.MatchedBy(addr)
		if ok != c.allowed {
			t.Fatalf("MatchedBy(%s) ok = %v, want %v", c.address, ok, c.allowed)
		}
		if ok && matched.String() != c.matched {
			t.Fatalf("MatchedBy(%s) = %q, want %q", c.address, matched.String(), c.matched)
		}
	}

	// Strings is what the API and the CLI display, in canonical form.
	got := rules.Strings()
	want := []string{"*@team.example", "lead@partner.example"}
	if len(got) != len(want) {
		t.Fatalf("Strings() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Strings() = %v, want %v", got, want)
		}
	}
}

// A pattern outside the grammar must be refused when the rules are built, not
// silently dropped: dropping one would widen the guardrail without saying so.
func TestRecipientRulesRefuseAnInvalidPattern(t *testing.T) {
	if _, err := NewRecipientRules([]string{"*@team.example", "not a pattern"}); err == nil {
		t.Fatal("NewRecipientRules accepted a pattern outside the grammar")
	}
	// And the grammar is the sender grammar: no new shapes are allowed here.
	for _, bad := range []string{"*", "*@*", "dev@*", "*@team.*", "dev@@team.example"} {
		if _, err := NewRecipientRules([]string{bad}); err == nil {
			t.Fatalf("NewRecipientRules accepted %q", bad)
		}
	}
}
