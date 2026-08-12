package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/amenitydev/relais/internal/crypto"
)

// cmdKeygen prints fresh key material for the environment.
//
// It touches nothing: no database, no files. Whoever runs it is responsible for
// getting the value into the secret store, and the value is printed once.
func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("relais keygen", flag.ContinueOnError)
	export := fs.Bool("export", false, "print as a shell export statement")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais keygen key|pepper [-export]

  key     A 32-byte AES key for RELAIS_SECRET_ENCRYPTION_KEYS (seals backend
          SMTP passwords; reversible, and rotatable by adding a second entry)
  pepper  A 32-byte HMAC key for RELAIS_SECRET_CREDENTIAL_PEPPER (fingerprints
          sender credentials; one-way, and NOT rotatable without re-issuing
          every credential)

Store both outside the repository. Losing the keyring makes backend passwords
unrecoverable; losing the pepper invalidates every credential.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	kind := "key"
	if fs.NArg() > 0 {
		kind = fs.Arg(0)
	}

	switch kind {
	case "key":
		value, err := crypto.GenerateKey()
		if err != nil {
			return err
		}
		// Key id 1 is the conventional first entry; a rotation adds "2:<key>"
		// and points RELAIS_SECRET_ENCRYPTION_ACTIVE_KEY at it.
		emit(*export, "RELAIS_SECRET_ENCRYPTION_KEYS", "1:"+value)
		return nil

	case "pepper":
		value, err := crypto.GeneratePepper()
		if err != nil {
			return err
		}
		emit(*export, "RELAIS_SECRET_CREDENTIAL_PEPPER", value)
		return nil

	default:
		fs.Usage()
		return fmt.Errorf("unknown keygen kind %q: want key or pepper", kind)
	}
}

func emit(export bool, name, value string) {
	if export {
		fmt.Printf("export %s=%q\n", name, value)
		return
	}
	fmt.Println(value)
	// The hint goes to stderr so that `relais keygen key > secret` captures only
	// the value.
	fmt.Fprintf(os.Stderr, "\nSet %s to the value above.\n", name)
}
