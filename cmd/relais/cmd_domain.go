package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/store"
)

func cmdDomain(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relais domain add|list|rm|resolve")
	}
	switch args[0] {
	case "add":
		return cmdDomainAdd(ctx, args[1:])
	case "list":
		return cmdDomainList(ctx, args[1:])
	case "rm":
		return cmdDomainRemove(ctx, args[1:])
	case "resolve":
		return cmdDomainResolve(ctx, args[1:])
	default:
		return fmt.Errorf("unknown domain action %q: want add, list, rm or resolve", args[0])
	}
}

func cmdDomainAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais domain add", flag.ContinueOnError)
	name := fs.String("name", "", "sending domain, e.g. example.com (required)")
	backend := fs.String("backend", "", "backend name or id (required)")
	includeSubdomains := fs.Bool("include-subdomains", false, "also route strict subdomains through this backend")
	disabled := fs.Bool("disabled", false, "create the domain without enabling it")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais domain add -name <domain> -backend <name|id> [flags]

Registers a sending domain and the backend that carries its mail. No DKIM
material is stored: signing happens downstream in the backend.

-include-subdomains is required for a "*@*.example.com" sender pattern to be
usable. Without it, such a pattern passes validation and then fails to resolve a
backend, which would turn an operator's configuration mistake into a delivery
failure.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *backend == "" {
		fs.Usage()
		return errors.New("-name and -backend are required")
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	backendID, backendName, err := resolveBackendRef(ctx, sess, *backend)
	if err != nil {
		return err
	}

	domain, err := sess.store.CreateDomain(ctx, store.NewDomainParams{
		Name:              *name,
		BackendID:         backendID,
		IncludeSubdomains: *includeSubdomains,
		Enabled:           !*disabled,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("domain %q is already registered", *name)
		}
		return err
	}

	fmt.Printf("created domain %s (%s) -> backend %s\n", domain.Name, domain.ID, backendName)
	if domain.Name != *name {
		// Say so when normalization changed the input, so the operator is not
		// surprised later by a name they did not type.
		fmt.Printf("  note: normalized from %q\n", *name)
	}
	fmt.Printf("  include_subdomains=%t  enabled=%t\n", domain.IncludeSubdomains, domain.Enabled)
	return nil
}

func cmdDomainList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais domain list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	domains, err := sess.store.ListDomains(ctx)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		fmt.Println("no domains configured")
		return nil
	}

	table := newTable()
	fmt.Fprintln(table, "DOMAIN\tBACKEND\tSUBDOMAINS\tENABLED\tID")
	for _, d := range domains {
		enabled := fmt.Sprintf("%t", d.Enabled)
		if d.Enabled && !d.BackendEnabled {
			// A domain pointing at a disabled backend cannot deliver; surfacing
			// it here saves a confusing debugging session.
			enabled = "true (backend disabled)"
		}
		fmt.Fprintf(table, "%s\t%s\t%t\t%s\t%s\n", d.Name, d.BackendName, d.IncludeSubdomains, enabled, d.ID)
	}
	return table.Flush()
}

func cmdDomainRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais domain rm", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: relais domain rm <id>")
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("%q is not a valid domain id: %w", fs.Arg(0), err)
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	if err := sess.store.DeleteDomain(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no domain with id %s", id)
		}
		return err
	}
	fmt.Printf("deleted domain %s\n", id)
	return nil
}

// cmdDomainResolve answers "which backend would carry mail from this address?"
// without sending anything. It is the quickest way to check that an
// include-subdomains setting does what the operator intended.
func cmdDomainResolve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais domain resolve", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: relais domain resolve <domain>\n\nShows which backend would carry mail from that sender domain.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one domain is required")
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	route, err := sess.store.ResolveSender(ctx, fs.Arg(0))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no enabled domain covers %q: a message from it would be rejected at ingestion", fs.Arg(0))
		}
		return err
	}

	fmt.Printf("%s -> domain %s -> backend %s\n", fs.Arg(0), route.DomainName, route.BackendName)
	fmt.Printf("  %s  tls=%s  auth=%t  max_concurrency=%d\n",
		route.Address(), route.TLSMode, route.UsesAuth(), route.MaxConcurrency)
	return nil
}

// resolveBackendRef accepts either a backend id or a backend name, because
// typing a uuid by hand is a poor experience.
func resolveBackendRef(ctx context.Context, sess *session, ref string) (uuid.UUID, string, error) {
	if id, err := uuid.Parse(ref); err == nil {
		backend, err := sess.store.GetBackend(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return uuid.Nil, "", fmt.Errorf("no backend with id %s", id)
			}
			return uuid.Nil, "", err
		}
		return backend.ID, backend.Name, nil
	}

	backend, err := sess.store.GetBackendByName(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return uuid.Nil, "", fmt.Errorf("no backend named %q (list them with `relais backend list`)", ref)
		}
		return uuid.Nil, "", err
	}
	return backend.ID, backend.Name, nil
}
