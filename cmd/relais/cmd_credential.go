package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/store"
)

func cmdCredential(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relais credential create|list|show|revoke|pattern")
	}
	switch args[0] {
	case "create":
		return cmdCredentialCreate(ctx, args[1:])
	case "list":
		return cmdCredentialList(ctx, args[1:])
	case "show":
		return cmdCredentialShow(ctx, args[1:])
	case "revoke":
		return cmdCredentialRevoke(ctx, args[1:])
	case "pattern":
		return cmdCredentialPattern(ctx, args[1:])
	default:
		return fmt.Errorf("unknown credential action %q: want create, list, show, revoke or pattern", args[0])
	}
}

// stringList collects a flag that may be repeated.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	// Accept both repeated flags and a comma-separated list, since operators
	// reach for either.
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			*l = append(*l, trimmed)
		}
	}
	return nil
}

func cmdCredentialCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais credential create", flag.ContinueOnError)
	name := fs.String("name", "", "human-readable name, unique (required)")
	kind := fs.String("type", store.CredentialTypeAPIKey, "api_key or smtp_user")
	username := fs.String("username", "", "SMTP username for -type smtp_user (generated when omitted)")
	var patterns stringList
	fs.Var(&patterns, "from", "allowed From pattern; repeat or comma-separate")
	rps := fs.Float64("rate-limit-rps", 0, "per-credential rate limit override, in requests per second")
	burst := fs.Int("rate-limit-burst", 0, "per-credential burst override")
	disabled := fs.Bool("disabled", false, "create the credential without enabling it")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais credential create -name <name> [-type api_key|smtp_user] [flags]

Mints a sender credential. The secret is printed once and is not recoverable:
only a fingerprint is stored, so there is nothing to read back.

Sender patterns take one of four shapes, and nothing else:

  no-reply@app.example.com    that exact address
  *@example.com               any local part, that exact domain
  no-reply@*.example.com      that local part, any subdomain
  *@*.example.com             any local part, any subdomain

Note that "*.example.com" does not include "example.com" itself. A credential
created with no pattern can send as nobody until one is added.

Examples:
  relais credential create -name billing-api -from 'invoices@billing.example.com'
  relais credential create -name wordpress -type smtp_user -username blog \
    -from '*@blog.example.com'

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return errors.New("-name is required")
	}

	params := store.NewCredentialParams{
		Name:         *name,
		Type:         *kind,
		SMTPUsername: *username,
		Patterns:     patterns,
		CreatedBy:    cliActor(),
		Enabled:      !*disabled,
	}
	if *rps > 0 {
		params.RateLimitRPS = rps
	}
	if *burst > 0 {
		value := int32(*burst)
		params.RateLimitBurst = &value
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	created, err := sess.store.CreateCredential(ctx, params)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			switch store.ConstraintName(err) {
			case "credential_name_key":
				return fmt.Errorf("a credential named %q already exists", *name)
			case "credential_lookup_key":
				return fmt.Errorf("the SMTP username %q is already taken", *username)
			}
		}
		return err
	}

	fmt.Printf("created credential %s (%s)\n", created.Credential.Name, created.Credential.ID)
	fmt.Printf("  type=%s  enabled=%t\n", created.Credential.Type, created.Credential.Enabled)

	if created.Credential.Type == store.CredentialTypeSMTPUser {
		fmt.Printf("\n  SMTP username: %s\n", created.Credential.Lookup)
		fmt.Printf("  SMTP password: %s\n", created.Secret.Reveal())
	} else {
		fmt.Printf("\n  API key: %s\n", created.Secret.Reveal())
	}

	// The whole point of the one-way fingerprint is that this is the only
	// chance to copy the value, so say so plainly.
	fmt.Fprintln(os.Stderr, "\nCopy the secret now: it is stored only as a fingerprint and cannot be shown again.")

	if len(created.Patterns) == 0 {
		fmt.Fprintln(os.Stderr, "\nWarning: no sender pattern is configured, so this credential cannot send anything yet.")
		fmt.Fprintf(os.Stderr, "Add one with: relais credential pattern add %s -from '<pattern>'\n", created.Credential.ID)
		return nil
	}
	fmt.Println("\n  allowed senders:")
	for _, p := range created.Patterns {
		fmt.Printf("    %s\n", p)
	}
	return nil
}

func cmdCredentialList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais credential list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	credentials, err := sess.store.ListCredentials(ctx)
	if err != nil {
		return err
	}
	if len(credentials) == 0 {
		fmt.Println("no credentials configured")
		return nil
	}

	table := newTable()
	fmt.Fprintln(table, "NAME\tTYPE\tLOOKUP\tPATTERNS\tSTATE\tLAST USED\tID")
	for _, c := range credentials {
		lastUsed := "never"
		if c.LastUsedAt != nil {
			lastUsed = c.LastUsedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			c.Name, c.Type, c.Lookup, c.PatternCount, credentialState(c.Enabled, c.RevokedAt != nil), lastUsed, c.ID)
	}
	return table.Flush()
}

func cmdCredentialShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais credential show", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: relais credential show <id>")
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("%q is not a valid credential id: %w", fs.Arg(0), err)
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	auth, err := sess.store.LoadCredential(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no credential with id %s", id)
		}
		return err
	}
	c := auth.Credential

	fmt.Printf("%s (%s)\n", c.Name, c.ID)
	fmt.Printf("  type=%s  lookup=%s  state=%s\n", c.Type, c.Lookup, credentialState(c.Enabled, c.RevokedAt != nil))
	fmt.Printf("  created=%s by %s\n", c.CreatedAt.Format("2006-01-02 15:04:05"), orDash(c.CreatedBy))
	if c.RevokedAt != nil {
		fmt.Printf("  revoked=%s\n", c.RevokedAt.Format("2006-01-02 15:04:05"))
	}

	stored, err := sess.store.ListPatterns(ctx, id)
	if err != nil {
		return err
	}
	if len(stored) == 0 {
		fmt.Println("\n  allowed senders: none (this credential cannot send anything)")
		return nil
	}
	fmt.Println("\n  allowed senders:")
	table := newTable()
	fmt.Fprintln(table, "  PATTERN\tPATTERN ID")
	for _, p := range stored {
		fmt.Fprintf(table, "  %s\t%s\n", p.Pattern, p.ID)
	}
	return table.Flush()
}

func cmdCredentialRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais credential revoke", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais credential revoke <id>

Revocation is immediate and permanent. There is no un-revoke: restoring access
means creating a new credential, which is deliberate, because a leaked secret
stays leaked.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one credential id is required")
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("%q is not a valid credential id: %w", fs.Arg(0), err)
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	revoked, err := sess.store.RevokeCredential(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no credential with id %s", id)
		}
		return err
	}
	fmt.Printf("revoked credential %s (%s) at %s\n", revoked.Name, revoked.ID, revoked.RevokedAt.Format("2006-01-02 15:04:05"))
	return nil
}

func cmdCredentialPattern(ctx context.Context, args []string) error {
	patternUsage := func(out *flag.FlagSet) func() {
		return func() {
			fmt.Fprint(out.Output(), `Usage:
  relais credential pattern add <credential-id> -from '<pattern>' [-from ...]
  relais credential pattern rm  <credential-id> <pattern-id>

Patterns are validated before insert, so an invalid one rejects the whole call
rather than leaving the allow-list half-changed.
`)
		}
	}

	if len(args) < 2 {
		fs := flag.NewFlagSet("relais credential pattern", flag.ContinueOnError)
		fs.Usage = patternUsage(fs)
		fs.Usage()
		return errors.New("an action and a credential id are required")
	}

	// The positional arguments are pulled out before flag parsing: the flag
	// package stops at the first non-flag argument, so "pattern add <id> -from x"
	// would otherwise silently ignore -from.
	action, idArg, flagArgs := args[0], args[1], args[2:]

	credentialID, err := uuid.Parse(idArg)
	if err != nil {
		return fmt.Errorf("%q is not a valid credential id: %w", idArg, err)
	}

	fs := flag.NewFlagSet("relais credential pattern "+action, flag.ContinueOnError)
	var patterns stringList
	fs.Var(&patterns, "from", "sender pattern; repeat or comma-separate")
	fs.Usage = patternUsage(fs)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	switch action {
	case "add":
		if len(patterns) == 0 {
			fs.Usage()
			return errors.New("at least one -from pattern is required")
		}
		added, err := sess.store.AddPatterns(ctx, credentialID, patterns)
		if err != nil {
			if errors.Is(err, store.ErrReference) {
				return fmt.Errorf("no credential with id %s", credentialID)
			}
			return err
		}
		for _, p := range added {
			fmt.Printf("allowed %s\n", p)
		}
		return nil

	case "rm":
		if fs.NArg() != 1 {
			fs.Usage()
			return errors.New("exactly one pattern id is required")
		}
		patternID, err := uuid.Parse(fs.Arg(0))
		if err != nil {
			return fmt.Errorf("%q is not a valid pattern id: %w", fs.Arg(0), err)
		}
		if err := sess.store.RemovePattern(ctx, credentialID, patternID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("credential %s has no pattern %s", credentialID, patternID)
			}
			return err
		}
		fmt.Printf("removed pattern %s\n", patternID)
		return nil

	default:
		fs.Usage()
		return fmt.Errorf("unknown pattern action %q: want add or rm", action)
	}
}

func credentialState(enabled, revoked bool) string {
	switch {
	case revoked:
		return "revoked"
	case !enabled:
		return "disabled"
	default:
		return "active"
	}
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// cliActor records who ran the command, for credential.created_by. It is
// best-effort: the admin API supplies a real OIDC subject instead.
func cliActor() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	host, err := os.Hostname()
	switch {
	case user != "" && err == nil:
		return "cli:" + user + "@" + host
	case user != "":
		return "cli:" + user
	default:
		return "cli"
	}
}
