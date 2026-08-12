package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/amenitydev/relais/internal/httpapi"
)

// cmdOpenAPI writes the OpenAPI document for one of the two surfaces.
//
// It needs no database and no configuration: the document is a property of the
// code, not of a deployment. That is what lets CI regenerate it and compare,
// exactly as it does with the sqlc output.
func cmdOpenAPI(args []string) error {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	surface := fs.String("surface", "admin", "which document: admin or public")
	out := fs.String("o", "", "write to this file instead of stdout")
	check := fs.String("check", "", "compare against this file and fail if it differs")
	version := fs.String("version", "", "the version to stamp (defaults to the API version)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: relais openapi [flags]

Emit the OpenAPI 3.1 description of an HTTP surface. The two listeners are
documented separately, because they are separately exposed.

Flags:
  -surface admin|public   Which document (default admin)
  -o PATH                 Write to PATH instead of stdout
  -check PATH             Compare against PATH; exit non-zero if it differs
  -version STRING         Version to stamp in info.version (default: the API version)

Examples:
  relais openapi -surface admin -o docs/openapi-admin.json
  relais openapi -surface public -check docs/openapi-public.json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *out != "" && *check != "" {
		return fmt.Errorf("-o and -check do the opposite of each other; pick one")
	}

	// The API version, not the build version. OpenAPI's info.version describes the
	// contract, and stamping the binary's version here would make the committed
	// document differ from a fresh one on every tagged build — turning CI's
	// comparison into noise that gets ignored, which is worse than not having it.
	stamp := *version
	if stamp == "" {
		stamp = httpapi.APIVersion
	}

	document, err := httpapi.OpenAPI(httpapi.Surface(*surface), stamp)
	if err != nil {
		return err
	}

	switch {
	case *check != "":
		return checkOpenAPI(*check, document, *surface)
	case *out != "":
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(*out, document, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *out, len(document))
		return nil
	default:
		_, err := os.Stdout.Write(document)
		return err
	}
}

// checkOpenAPI compares a committed document against a freshly generated one.
//
// The message names the command that fixes it, because the person who sees this
// failure is usually someone who changed a handler and has no reason to know that
// a document is generated from it.
func checkOpenAPI(path string, fresh []byte, surface string) error {
	committed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if string(committed) == string(fresh) {
		return nil
	}
	return fmt.Errorf("%s is out of date: regenerate it with\n"+
		"\trelais openapi -surface %s -o %s\n"+
		"or run `task openapi`", path, surface, path)
}
