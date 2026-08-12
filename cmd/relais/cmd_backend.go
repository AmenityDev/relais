package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/store"
)

func cmdBackend(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relais backend add|list|rm|rewrap")
	}
	switch args[0] {
	case "add":
		return cmdBackendAdd(ctx, args[1:])
	case "list":
		return cmdBackendList(ctx, args[1:])
	case "rm":
		return cmdBackendRemove(ctx, args[1:])
	case "rewrap":
		return cmdBackendRewrap(ctx, args[1:])
	default:
		return fmt.Errorf("unknown backend action %q: want add, list, rm or rewrap", args[0])
	}
}

func cmdBackendAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais backend add", flag.ContinueOnError)
	name := fs.String("name", "", "backend name, unique (required)")
	host := fs.String("host", "", "backend hostname (required)")
	port := fs.Int("port", 587, "backend port")
	tlsMode := fs.String("tls", store.TLSModeSTARTTLS, "starttls, tls or none")
	authUser := fs.String("user", "", "SMTP AUTH username")
	passwordStdin := fs.Bool("password-stdin", false, "read the SMTP AUTH password from stdin instead of prompting")
	helo := fs.String("helo", "", "EHLO name to present (defaults to the configured SMTP domain)")
	maxConcurrency := fs.Int("max-concurrency", 2, "simultaneous deliveries allowed to this backend")
	disabled := fs.Bool("disabled", false, "create the backend without enabling it")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais backend add -name <name> -host <host> [flags]

Registers an outbound relay. For OCI Email Delivery this is typically:

  relais backend add -name oci-eu-zurich \
    -host smtp.email.eu-zurich-1.oci.oraclecloud.com -port 587 \
    -tls starttls -user 'ocid1.user.oc1..aaaa@ocid1.tenancy.oc1..bbbb.xy.com'

The password is prompted for (never passed as an argument, where it would land
in the shell history and in ps output) and stored sealed with the active
encryption key.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *host == "" {
		fs.Usage()
		return errors.New("-name and -host are required")
	}

	var password crypto.Secret
	if *authUser != "" {
		value, err := readSecret("SMTP AUTH password: ", *passwordStdin)
		if err != nil {
			return err
		}
		if value == "" {
			return errors.New("an empty password was supplied for a backend that uses SMTP AUTH")
		}
		password = crypto.Secret(value)
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	backend, err := sess.store.CreateBackend(ctx, store.NewBackendParams{
		Name:           *name,
		Host:           *host,
		Port:           int32(*port),
		TLSMode:        *tlsMode,
		AuthUser:       *authUser,
		AuthPassword:   password,
		HeloName:       *helo,
		MaxConcurrency: int32(*maxConcurrency),
		Enabled:        !*disabled,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("a backend named %q already exists", *name)
		}
		return err
	}

	fmt.Printf("created backend %s (%s)\n", backend.Name, backend.ID)
	fmt.Printf("  %s:%d  tls=%s  auth=%s  max_concurrency=%d  enabled=%t\n",
		backend.Host, backend.Port, backend.TlsMode, authDescription(backend.AuthUser), backend.MaxConcurrency, backend.Enabled)
	return nil
}

func cmdBackendList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais backend list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	backends, err := sess.store.ListBackends(ctx)
	if err != nil {
		return err
	}
	if len(backends) == 0 {
		fmt.Println("no backends configured")
		return nil
	}

	table := newTable()
	fmt.Fprintln(table, "NAME\tADDRESS\tTLS\tAUTH\tCONC\tENABLED\tID")
	for _, b := range backends {
		fmt.Fprintf(table, "%s\t%s:%d\t%s\t%s\t%d\t%t\t%s\n",
			b.Name, b.Host, b.Port, b.TlsMode, authDescription(b.AuthUser), b.MaxConcurrency, b.Enabled, b.ID)
	}
	return table.Flush()
}

func cmdBackendRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais backend rm", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: relais backend rm <id>\n\nFails while any domain still routes through the backend.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one backend id is required")
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("%q is not a valid backend id: %w", fs.Arg(0), err)
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	if err := sess.store.DeleteBackend(ctx, id); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("no backend with id %s", id)
		case errors.Is(err, store.ErrReference):
			return fmt.Errorf("backend %s still has domains routed through it: move or delete them first", id)
		default:
			return err
		}
	}
	fmt.Printf("deleted backend %s\n", id)
	return nil
}

// cmdBackendRewrap completes a key rotation by re-sealing every stored password
// under the active key, after which the retired key can be dropped from the
// environment.
func cmdBackendRewrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais backend rewrap", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais backend rewrap

Re-seals every backend password under the active encryption key.

Rotation procedure:
  1. Add a new key:  RELAIS_SECRET_ENCRYPTION_KEYS="1:<old>,2:<new>"
  2. Make it active: RELAIS_SECRET_ENCRYPTION_ACTIVE_KEY=2
  3. Run this command
  4. Remove the old entry from RELAIS_SECRET_ENCRYPTION_KEYS

Skipping step 3 leaves rows that only the old key can open, so step 4 would
strand them.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	count, err := sess.store.RewrapBackendPasswords(ctx)
	if err != nil {
		return err
	}
	switch count {
	case 0:
		fmt.Println("every backend password is already sealed under the active key")
	case 1:
		fmt.Println("re-sealed 1 backend password")
	default:
		fmt.Printf("re-sealed %d backend passwords\n", count)
	}
	return nil
}

func authDescription(user string) string {
	if user == "" {
		return "-"
	}
	// The username can be very long for OCI; keep the table readable.
	if len(user) > 28 {
		return user[:25] + "..."
	}
	return user
}

// readSecret reads a secret without echoing it.
//
// Secrets are never accepted as command-line arguments: an argument is visible
// in the shell history and in the process list of every user on the box.
func readSecret(prompt string, fromStdin bool) (string, error) {
	if fromStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("read password from stdin: %w", err)
			}
			return "", errors.New("no password on stdin")
		}
		return strings.TrimRight(scanner.Text(), "\r\n"), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal: pass -password-stdin to read the password from a pipe")
	}

	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}
