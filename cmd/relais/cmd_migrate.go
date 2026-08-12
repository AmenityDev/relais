package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/amenitydev/relais/internal/db"
)

// cmdMigrate applies, rolls back or inspects the schema.
//
// Migrations are never run implicitly by `serve`. With several replicas behind a
// rolling deploy, an implicit migration turns every restart into a race; making
// it an explicit step means the operator decides when the schema changes.
func cmdMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais migrate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais migrate up|down|status

  up      Apply every pending migration, application schema then river schema
  down    Roll back the most recent application migration
  status  List applied and pending application migrations

Both schemas migrate while holding a Postgres advisory lock, so concurrent
replicas cannot race.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	action := "up"
	if fs.NArg() > 0 {
		action = fs.Arg(0)
	}

	// Migrations do not need the key material: they touch no secret.
	sess, err := openSession(ctx, false)
	if err != nil {
		return err
	}
	defer sess.Close()

	switch action {
	case "up":
		res, err := db.MigrateUp(ctx, sess.pool, sess.log)
		if err != nil {
			return err
		}
		if res.Empty() {
			fmt.Println("schema already up to date")
			return nil
		}
		for _, step := range res.AppSteps {
			fmt.Println("applied", step)
		}
		for _, step := range res.RiverSteps {
			fmt.Println("applied", step)
		}
		return nil

	case "down":
		res, err := db.MigrateDown(ctx, sess.pool, sess.log)
		if err != nil {
			return err
		}
		if res.Empty() {
			fmt.Println("nothing to roll back")
			return nil
		}
		for _, step := range res.AppSteps {
			fmt.Println("rolled back", step)
		}
		return nil

	case "status":
		rows, err := db.MigrateStatus(ctx, sess.pool)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("no migrations found")
			return nil
		}
		table := newTable()
		fmt.Fprintln(table, "VERSION\tSTATE\tSOURCE")
		for _, row := range rows {
			fmt.Fprintf(table, "%d\t%s\t%s\n", row.Version, row.State, row.Source)
		}
		return table.Flush()

	default:
		fs.Usage()
		return fmt.Errorf("unknown migrate action %q", action)
	}
}
