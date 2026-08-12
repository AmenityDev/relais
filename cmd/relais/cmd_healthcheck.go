package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cmdHealthcheck probes the local readiness endpoint and exits non-zero when it
// is not ready.
//
// It exists so that a distroless image, which has no shell and no curl, can
// still declare a Docker HEALTHCHECK: the binary probes itself.
func cmdHealthcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais healthcheck", flag.ContinueOnError)
	url := fs.String("url", "", "readiness URL (defaults to the configured HTTP address)")
	timeout := fs.Duration("timeout", 3*time.Second, "probe timeout")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais healthcheck [-url http://127.0.0.1:8080/readyz] [-timeout 3s]

Probes the readiness endpoint and exits 0 only when the service reports ready.
Intended for a container HEALTHCHECK, where no shell is available.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := *url
	if target == "" {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		target = readinessURL(cfg.HTTP.Addr)
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("build probe request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("probe %s: %w", target, err)
	}
	defer resp.Body.Close()
	// Draining lets the connection be reused and keeps the server from logging a
	// broken pipe.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: %s", target, resp.Status)
	}
	return nil
}

// readinessURL turns a listen address into a loopback probe URL. A bare ":8080"
// or "0.0.0.0:8080" must be probed on 127.0.0.1, not on the wildcard address.
func readinessURL(addr string) string {
	host, port, found := strings.Cut(addr, ":")
	if !found {
		return "http://127.0.0.1:8080/readyz"
	}
	switch host {
	case "", "0.0.0.0", "[::]", "::":
		host = "127.0.0.1"
	}
	return "http://" + host + ":" + port + "/readyz"
}
