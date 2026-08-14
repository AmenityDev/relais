# Contributing

Thank you for looking. relais is a small, opinionated service, and the fastest way to
get a change merged is to know what it is trying to be — [the
README](README.md#what-it-is-not) says what it deliberately is not, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains why the code is shaped the way it
is.

## Before writing code

**Open an issue first for anything beyond a fix.** Not as a formality: several things
that look like obvious improvements are deliberate omissions, and it is unpleasant to
find that out after writing the patch. Bounce handling, templates, tracking and
multi-tenancy are all in that category.

Bug reports are more useful with the failing case than with a diagnosis. If you have
both, better still.

For anything with security consequences, read [SECURITY.md](SECURITY.md) first — please
do not open a public issue for a vulnerability.

## Getting set up

The [Quick start](README.md#quick-start) brings up the whole stack, including an OIDC
provider with its realm pre-imported. `task` lists every target.

```sh
task lint        # vet, gofmt, module tidiness, OpenAPI freshness
task test:all    # the Go suite, requiring the relais_test database
task web:check   # the frontend: types, format, lint, unit tests
task smoke       # drive the running stack end to end
```

CI runs the same things. It is worth running `task lint` before pushing, since the
OpenAPI check catches the most common oversight: changing a handler's request or
response type without regenerating the documents (`task openapi`) and the frontend
types (`task web:types`).

## What the review will look at

**Does a change to the sender-pattern grammar come with fuzzing?**
`internal/frompattern` decides what every credential is allowed to send as. It is the
most security-sensitive code here, its grammar is closed on purpose, and no
user-supplied regular expression is ever evaluated. Changes there are held to a
different standard than the rest.

**Is the failure mode loud?** A recurring theme in this codebase, and in the mistakes
recorded at the end of `docs/ARCHITECTURE.md`, is that a silent failure costs far more
than a noisy one. A configuration that cannot work should stop the process; a check
that cannot run should fail rather than skip.

**Does a test prove what it claims?** Several tests here were written, passed, and
turned out to assert nothing — a skipped integration suite that read as a pass, a check
that grepped for a value the page merely carried in its data. If a guard matters,
break it on purpose once and watch the test fail.

**Do comments explain the why?** The code is commented densely, but the comments are
about decisions and traps, not about what the next line does. A comment that could be
deleted without losing anything probably should be.

## Style

Go is formatted with `gofmt`; the frontend with Prettier, both enforced in CI. There is
no separate style guide — match the file you are editing.

Commits: a short imperative subject, and a body that says why when the diff does not
make it obvious. History is not squashed on merge, so a series of small commits with
clear messages is welcome.

## License

Contributions are accepted under [AGPL-3.0](LICENSE), the licence this project is
released under. By opening a pull request you confirm you have the right to contribute
the code under it.
