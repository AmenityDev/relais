package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/frompattern"
	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/store"
)

// --- identity and stats -----------------------------------------------------

// handleIdentity reports who the caller is.
//
// The frontend needs this to decide whether to render write controls. Without it
// the UI would have to decode the token, and keeping the token out of the browser
// is the whole point of the BFF design.
func (s *AdminServer) handleIdentity(w http.ResponseWriter, r *http.Request) {
	identity, ok := identityFrom(r.Context())
	if !ok {
		writeInternal(w, s.log, "no identity on an authenticated admin route", errors.New("missing identity"))
		return
	}

	groups := identity.Groups
	if groups == nil {
		groups = []string{}
	}
	writeJSON(w, http.StatusOK, identityResponse{
		Subject:  identity.Subject,
		Email:    identity.Email,
		Name:     identity.Name,
		Role:     string(identity.Role),
		CanWrite: identity.CanWrite(),
		Groups:   groups,
	})
}

// handleStats is the dashboard payload.
func (s *AdminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	byStatus, err := s.store.CountByStatus(r.Context())
	if err != nil {
		s.writeStoreError(w, "count messages", err)
		return
	}
	// Every known status is present even at zero, so a dashboard never has to
	// guess which keys might be missing.
	messages := map[string]int64{
		store.StatusQueued: 0, store.StatusSending: 0, store.StatusSent: 0,
		store.StatusFailed: 0, store.StatusRejected: 0,
	}
	for status, total := range byStatus {
		messages[status] = total
	}

	backends, err := s.store.ListBackends(r.Context())
	if err != nil {
		s.writeStoreError(w, "list backends", err)
		return
	}
	domains, err := s.store.ListDomains(r.Context())
	if err != nil {
		s.writeStoreError(w, "list domains", err)
		return
	}
	credentials, err := s.store.ListCredentials(r.Context())
	if err != nil {
		s.writeStoreError(w, "list credentials", err)
		return
	}

	byState := map[string]int{"active": 0, "disabled": 0, "revoked": 0}
	for _, credential := range credentials {
		byState[credentialState(credential.Enabled, credential.RevokedAt)]++
	}

	writeJSON(w, http.StatusOK, statsResponse{
		Messages:    messages,
		Backends:    len(backends),
		Domains:     len(domains),
		Credentials: byState,
	})
}

// --- backends ---------------------------------------------------------------

func (s *AdminServer) handleListBackends(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListBackends(r.Context())
	if err != nil {
		s.writeStoreError(w, "list backends", err)
		return
	}
	out := make([]backendResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, newBackendResponse(row))
	}
	writeJSON(w, http.StatusOK, listResponse[backendResponse]{Data: out})
}

// backendRequest is the create and update payload.
type backendRequest struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int32  `json:"port"`
	TLSMode string `json:"tls_mode"`

	AuthUser string `json:"auth_user"`
	// Password is write-only. It is never returned by any endpoint, because relais
	// cannot show it: it is stored sealed and only the worker ever opens it.
	Password *string `json:"password"`

	HeloName       string `json:"helo_name"`
	MaxConcurrency int32  `json:"max_concurrency"`
	Enabled        *bool  `json:"enabled"`
}

func (s *AdminServer) handleCreateBackend(w http.ResponseWriter, r *http.Request) {
	var request backendRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	password := ""
	if request.Password != nil {
		password = *request.Password
	}

	row, err := s.store.CreateBackend(r.Context(), store.NewBackendParams{
		Name: request.Name, Host: request.Host, Port: request.Port,
		TLSMode: request.TLSMode, AuthUser: request.AuthUser,
		AuthPassword: crypto.Secret(password),
		HeloName:     request.HeloName, MaxConcurrency: request.MaxConcurrency,
		Enabled: enabled,
	})
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "", err)
			return
		}
		s.writeStoreError(w, "create backend", err)
		return
	}

	s.audit(r, "backend created", "backend", row.ID.String(), row.Name)
	writeJSON(w, http.StatusCreated, newBackendResponse(row))
}

func (s *AdminServer) handleUpdateBackend(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	existing, err := s.store.GetBackend(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get backend", err)
		return
	}

	// The current values are the defaults, so a PATCH that omits a field leaves it
	// alone rather than resetting it to a zero value.
	request := backendRequest{
		Name: existing.Name, Host: existing.Host, Port: existing.Port,
		TLSMode: existing.TlsMode, AuthUser: existing.AuthUser,
		HeloName: existing.HeloName, MaxConcurrency: existing.MaxConcurrency,
	}
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	enabled := existing.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	params := store.UpdateBackendParams{
		ID: id, Name: request.Name, Host: request.Host, Port: request.Port,
		TLSMode: request.TLSMode, AuthUser: request.AuthUser,
		HeloName: request.HeloName, MaxConcurrency: request.MaxConcurrency,
		Enabled: enabled,
	}
	// An absent password keeps the stored one. Treating absent as "clear it" would
	// wipe a credential every time an admin renamed a backend.
	if request.Password != nil {
		params.RotatePassword = true
		params.AuthPassword = crypto.Secret(*request.Password)
	}

	row, err := s.store.UpdateBackend(r.Context(), params)
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "", err)
			return
		}
		s.writeStoreError(w, "update backend", err)
		return
	}

	s.audit(r, "backend updated", "backend", row.ID.String(), row.Name)
	writeJSON(w, http.StatusOK, newBackendResponse(row))
}

func (s *AdminServer) handleDeleteBackend(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteBackend(r.Context(), id); err != nil {
		s.writeStoreError(w, "delete backend", err)
		return
	}
	s.audit(r, "backend deleted", "backend", id.String(), "")
	w.WriteHeader(http.StatusNoContent)
}

// handleProbeBackend opens a connection and authenticates without sending
// anything.
//
// This is the endpoint that turns "I typed the OCI credentials in" into a yes or
// no, instead of waiting for a queue of failed deliveries to answer.
func (s *AdminServer) handleProbeBackend(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if s.prober == nil {
		writeError(w, http.StatusServiceUnavailable, errorBody{
			Code:    codeUnavailable,
			Message: "connection testing is not available in this process",
		})
		return
	}

	backend, err := s.store.GetBackend(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get backend", err)
		return
	}
	password, err := s.store.OpenBackendPassword(backend.AuthPasswordSealed)
	if err != nil {
		// The key that sealed this password is gone from the environment. That is
		// an operator problem worth naming precisely.
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code:    codeInvalidRequest,
			Message: "the stored password cannot be opened: " + err.Error(),
		})
		return
	}

	route := store.SenderRoute{
		BackendID: backend.ID, BackendName: backend.Name,
		Host: backend.Host, Port: backend.Port, TLSMode: backend.TlsMode,
		AuthUser: backend.AuthUser, AuthPassword: password,
		HeloName: backend.HeloName, MaxConcurrency: backend.MaxConcurrency,
	}

	result, probeErr := s.prober.Probe(r.Context(), route)
	if probeErr != nil {
		s.audit(r, "backend connection test failed", "backend", backend.ID.String(), backend.Name)
		// 200 with ok=false: the request succeeded, the connection did not, and a
		// UI showing a form error is the right rendering.
		writeJSON(w, http.StatusOK, probeResponse{
			OK: false,
			Error: &messageError{
				Code:   sender.CodeOf(probeErr),
				Detail: probeErr.Error(),
			},
		})
		return
	}

	s.audit(r, "backend connection tested", "backend", backend.ID.String(), backend.Name)
	writeJSON(w, http.StatusOK, probeResponse{
		OK:            true,
		UsedTLS:       result.UsedTLS,
		Authenticated: result.Authenticated,
		Extensions:    result.Extensions,
	})
}

// --- domains ----------------------------------------------------------------

func (s *AdminServer) handleListDomains(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListDomains(r.Context())
	if err != nil {
		s.writeStoreError(w, "list domains", err)
		return
	}
	out := make([]domainResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, newDomainListResponse(row))
	}
	writeJSON(w, http.StatusOK, listResponse[domainResponse]{Data: out})
}

type domainRequest struct {
	Name              string `json:"name"`
	BackendID         string `json:"backend_id"`
	IncludeSubdomains *bool  `json:"include_subdomains"`
	Enabled           *bool  `json:"enabled"`
}

func (s *AdminServer) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var request domainRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	backendID, err := uuid.Parse(strings.TrimSpace(request.BackendID))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code: codeInvalidRequest, Field: "backend_id",
			Message: "backend_id must be a valid id",
		})
		return
	}

	params := store.NewDomainParams{Name: request.Name, BackendID: backendID, Enabled: true}
	if request.IncludeSubdomains != nil {
		params.IncludeSubdomains = *request.IncludeSubdomains
	}
	if request.Enabled != nil {
		params.Enabled = *request.Enabled
	}

	row, err := s.store.CreateDomain(r.Context(), params)
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "name", err)
			return
		}
		s.writeStoreError(w, "create domain", err)
		return
	}

	s.audit(r, "domain created", "domain", row.ID.String(), row.Name)
	writeJSON(w, http.StatusCreated, newDomainResponse(row))
}

func (s *AdminServer) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	existing, err := s.store.GetDomainByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get domain", err)
		return
	}

	request := domainRequest{Name: existing.Name, BackendID: existing.SmtpBackendID.String()}
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	backendID, err := uuid.Parse(strings.TrimSpace(request.BackendID))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code: codeInvalidRequest, Field: "backend_id",
			Message: "backend_id must be a valid id",
		})
		return
	}

	params := store.NewDomainParams{
		Name: request.Name, BackendID: backendID,
		IncludeSubdomains: existing.IncludeSubdomains, Enabled: existing.Enabled,
	}
	if request.IncludeSubdomains != nil {
		params.IncludeSubdomains = *request.IncludeSubdomains
	}
	if request.Enabled != nil {
		params.Enabled = *request.Enabled
	}

	row, err := s.store.UpdateDomain(r.Context(), id, params)
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "name", err)
			return
		}
		s.writeStoreError(w, "update domain", err)
		return
	}

	s.audit(r, "domain updated", "domain", row.ID.String(), row.Name)
	writeJSON(w, http.StatusOK, newDomainResponse(row))
}

func (s *AdminServer) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteDomain(r.Context(), id); err != nil {
		s.writeStoreError(w, "delete domain", err)
		return
	}
	s.audit(r, "domain deleted", "domain", id.String(), "")
	w.WriteHeader(http.StatusNoContent)
}

// handleResolveDomain answers "which backend would carry mail from this sender?".
//
// A dry run, and the fastest way to check that an include_subdomains setting does
// what the operator meant.
func (s *AdminServer) handleResolveDomain(w http.ResponseWriter, r *http.Request) {
	senderAddress := strings.TrimSpace(r.URL.Query().Get("sender"))
	if senderAddress == "" {
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code: codeInvalidRequest, Field: "sender",
			Message: "a sender address or domain is required",
		})
		return
	}

	// Accept either a full address or a bare domain: an operator debugging a
	// rejection has an address in hand, not a domain.
	domain := senderAddress
	if addr, err := frompattern.ParseAddress(senderAddress); err == nil {
		domain = addr.Domain
	}

	route, err := s.store.ResolveSender(r.Context(), domain)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusOK, resolveResponse{
			Sender:   senderAddress,
			Resolved: false,
			Reason:   "no enabled domain covers " + domain + " (a parent domain needs include_subdomains for a subdomain to resolve)",
		})
		return
	case isValidationError(err):
		writeValidationError(w, "sender", err)
		return
	case err != nil:
		s.writeStoreError(w, "resolve sender", err)
		return
	}

	writeJSON(w, http.StatusOK, resolveResponse{
		Sender:     senderAddress,
		Resolved:   true,
		DomainName: route.DomainName,
		BackendID:  route.BackendID.String(),
		Backend:    route.BackendName,
		Address:    route.Address(),
		TLSMode:    route.TLSMode,
		UsesAuth:   route.UsesAuth(),
	})
}

// --- credentials ------------------------------------------------------------

func (s *AdminServer) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListCredentials(r.Context())
	if err != nil {
		s.writeStoreError(w, "list credentials", err)
		return
	}
	out := make([]credentialResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, credentialResponse{
			ID: row.ID.String(), Name: row.Name, Type: row.Type, Lookup: row.Lookup,
			State: credentialState(row.Enabled, row.RevokedAt), Enabled: row.Enabled,
			RateLimitRPS: row.RateLimitRps, RateLimitBurst: row.RateLimitBurst,
			PatternCount: row.PatternCount, CreatedBy: row.CreatedBy,
			CreatedAt:  row.CreatedAt.UTC().Format(timeLayout),
			LastUsedAt: rfc3339(row.LastUsedAt), RevokedAt: rfc3339(row.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, listResponse[credentialResponse]{Data: out})
}

func (s *AdminServer) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	auth, err := s.store.LoadCredential(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get credential", err)
		return
	}
	writeJSON(w, http.StatusOK, newCredentialResponse(auth.Credential, int64(auth.Patterns.Len())))
}

type createCredentialRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Username applies to a smtp_user credential. Empty asks relais to generate
	// one, which is the right default for machine-to-machine use.
	Username string   `json:"username"`
	Patterns []string `json:"patterns"`

	RateLimitRPS   *float64 `json:"rate_limit_rps"`
	RateLimitBurst *int32   `json:"rate_limit_burst"`
	Enabled        *bool    `json:"enabled"`
}

func (s *AdminServer) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	identity, _ := identityFrom(r.Context())

	var request createCredentialRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	created, err := s.store.CreateCredential(r.Context(), store.NewCredentialParams{
		Name: request.Name, Type: request.Type, SMTPUsername: request.Username,
		Patterns: request.Patterns, RateLimitRPS: request.RateLimitRPS,
		RateLimitBurst: request.RateLimitBurst,
		// The OIDC subject, so the audit trail names a person rather than "the API".
		CreatedBy: identity.String(),
		Enabled:   enabled,
	})
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, credentialField(err), err)
			return
		}
		s.writeStoreError(w, "create credential", err)
		return
	}

	s.audit(r, "credential created", "credential", created.Credential.ID.String(), created.Credential.Name)

	writeJSON(w, http.StatusCreated, showOnce(created,
		"This secret is shown once and cannot be recovered: relais stores only a "+
			"fingerprint of it."))
}

// showOnce builds the only response shape that carries a secret in the clear.
//
// Creation and rotation share it rather than each assembling their own, because
// the parts that are easy to forget — saying the value cannot be shown again,
// carrying the SMTP username next to its password, warning about an allow-list
// that permits nothing — are exactly the parts that make the response usable.
func showOnce(created store.CreatedCredential, warning string) createdCredentialResponse {
	patterns := created.Patterns
	if patterns == nil {
		patterns = []string{}
	}
	response := createdCredentialResponse{
		Credential: newCredentialResponse(created.Credential, int64(len(patterns))),
		Secret:     created.Secret.Reveal(),
		Patterns:   patterns,
		Warning:    warning,
	}
	if created.Credential.Type == store.CredentialTypeSMTPUser {
		response.Username = created.Credential.Lookup
	}
	if len(patterns) == 0 {
		response.Warning += " No sender pattern is configured, so this credential cannot send anything yet."
	}
	return response
}

type updateCredentialRequest struct {
	Name           string   `json:"name"`
	Enabled        *bool    `json:"enabled"`
	RateLimitRPS   *float64 `json:"rate_limit_rps"`
	RateLimitBurst *int32   `json:"rate_limit_burst"`
}

func (s *AdminServer) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	auth, err := s.store.LoadCredential(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get credential", err)
		return
	}

	request := updateCredentialRequest{
		Name:           auth.Credential.Name,
		RateLimitRPS:   auth.Credential.RateLimitRps,
		RateLimitBurst: auth.Credential.RateLimitBurst,
	}
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	enabled := auth.Credential.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	// A revoked credential cannot be re-enabled: relais holds no secret to restore
	// access with, so "un-revoke" would produce a credential nobody can use.
	if auth.Credential.RevokedAt != nil && enabled {
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code:  codeInvalidRequest,
			Field: "enabled",
			Message: "a revoked credential cannot be re-enabled: revocation is permanent, " +
				"so restoring access means creating a new credential",
		})
		return
	}

	row, err := s.store.UpdateCredential(r.Context(), store.UpdateCredentialParams{
		ID: id, Name: request.Name, Enabled: enabled,
		RateLimitRPS: request.RateLimitRPS, RateLimitBurst: request.RateLimitBurst,
	})
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "", err)
			return
		}
		s.writeStoreError(w, "update credential", err)
		return
	}

	s.audit(r, "credential updated", "credential", row.ID.String(), row.Name)
	writeJSON(w, http.StatusOK, newCredentialResponse(row, int64(auth.Patterns.Len())))
}

func (s *AdminServer) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	row, err := s.store.RevokeCredential(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "revoke credential", err)
		return
	}

	// Revocation is the admin action most worth having in an audit trail.
	s.audit(r, "credential revoked", "credential", row.ID.String(), row.Name)
	writeJSON(w, http.StatusOK, newCredentialResponse(row, 0))
}

// handleRotateCredential replaces the secret and keeps everything else.
//
// The alternative an operator has without this — create a replacement, revoke the
// old one — also throws away the allow-list somebody reviewed, the rate limits
// somebody tuned, and the id every past message points at. Rotating changes only
// the thing that leaked.
func (s *AdminServer) handleRotateCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	rotated, err := s.store.RotateCredentialSecret(r.Context(), id)
	if err != nil {
		// A revoked credential is refused here, which is the same rule the update
		// path enforces for "enabled": revocation is permanent either way.
		if isValidationError(err) {
			writeValidationError(w, "", err)
			return
		}
		s.writeStoreError(w, "rotate credential", err)
		return
	}

	// Audited for the same reason revocation is: a secret a client held stopped
	// working at a particular moment, and somebody will need to know when.
	s.audit(r, "credential secret rotated", "credential",
		rotated.Credential.ID.String(), rotated.Credential.Name)

	// 200, not 201: no resource came into being. The same body as creation, because
	// the operator's problem is identical — copy this now or lose it.
	writeJSON(w, http.StatusOK, showOnce(rotated,
		"The previous secret stopped working the moment this was issued. The new one is "+
			"shown once and cannot be recovered: relais stores only a fingerprint of it."))
}

// handleDeleteCredential removes the row, which revoking deliberately does not.
//
// The messages it sent survive — email_message.credential_id is ON DELETE SET
// NULL — but they stop naming it, so the audit trail loses who submitted them.
// That is the trade, and it is why revoke remains the answer to a leak.
func (s *AdminServer) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteCredential(r.Context(), id); err != nil {
		s.writeStoreError(w, "delete credential", err)
		return
	}
	// The id only, as for backends and domains: the delete returns a row count,
	// not a row, and reading the name first would fail on precisely the credential
	// most worth deleting — one carrying a pattern that no longer parses.
	s.audit(r, "credential deleted", "credential", id.String(), "")
	w.WriteHeader(http.StatusNoContent)
}

// --- patterns ---------------------------------------------------------------

func (s *AdminServer) handleListPatterns(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	// Confirms the credential exists, so an unknown id is a 404 rather than an
	// empty list that looks like a credential with no patterns.
	if _, err := s.store.LoadCredential(r.Context(), id); err != nil {
		s.writeStoreError(w, "get credential", err)
		return
	}

	rows, err := s.store.ListPatterns(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "list patterns", err)
		return
	}
	out := make([]patternResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, newPatternResponse(row))
	}
	writeJSON(w, http.StatusOK, listResponse[patternResponse]{Data: out})
}

type addPatternsRequest struct {
	Patterns []string `json:"patterns"`
}

func (s *AdminServer) handleAddPatterns(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	var request addPatternsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	added, err := s.store.AddPatterns(r.Context(), id, request.Patterns)
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "patterns", err)
			return
		}
		s.writeStoreError(w, "add patterns", err)
		return
	}

	// What a credential may send as is the security-relevant change, so it is
	// audited with the patterns themselves.
	s.audit(r, "sender patterns granted", "credential", id.String(), strings.Join(added, ", "))

	rows, err := s.store.ListPatterns(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "list patterns", err)
		return
	}
	out := make([]patternResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, newPatternResponse(row))
	}
	writeJSON(w, http.StatusCreated, listResponse[patternResponse]{Data: out})
}

func (s *AdminServer) handleDeletePattern(w http.ResponseWriter, r *http.Request) {
	credentialID, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}
	patternID, ok := s.pathUUID(w, r, "patternID")
	if !ok {
		return
	}

	if err := s.store.RemovePattern(r.Context(), credentialID, patternID); err != nil {
		s.writeStoreError(w, "remove pattern", err)
		return
	}
	s.audit(r, "sender pattern revoked", "credential", credentialID.String(), patternID.String())
	w.WriteHeader(http.StatusNoContent)
}

type validatePatternRequest struct {
	Pattern string `json:"pattern"`
}

// handleValidatePattern is the dry run of the grammar.
//
// It exists so the frontend never reimplements it. A TypeScript copy would drift,
// and the day it drifts the UI tells an operator a pattern covers more, or less,
// than it does.
func (s *AdminServer) handleValidatePattern(w http.ResponseWriter, r *http.Request) {
	var request validatePatternRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	parsed, err := frompattern.Parse(request.Pattern)
	if err != nil {
		// 200, not 422: "this pattern is invalid" is the successful answer to
		// "is this pattern valid?".
		writeJSON(w, http.StatusOK, patternValidationResponse{Valid: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, patternValidationResponse{
		Valid: true,
		// The canonical form is the point: an operator typing "Exemplé.COM" should
		// see the punycode before saving, not discover it afterwards.
		Normalized:  parsed.String(),
		Explanation: explainPattern(parsed.String()),
	})
}

type testPatternRequest struct {
	Address string `json:"address"`
}

// handleTestPattern answers "would this credential be allowed to send as this
// address?" — the endpoint that saves an hour of debugging per configuration.
func (s *AdminServer) handleTestPattern(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	var request testPatternRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	result, err := s.store.TestPattern(r.Context(), id, request.Address)
	if err != nil {
		if isValidationError(err) {
			writeValidationError(w, "address", err)
			return
		}
		s.writeStoreError(w, "test pattern", err)
		return
	}
	writeJSON(w, http.StatusOK, newPatternTestResponse(result))
}

// --- messages ---------------------------------------------------------------

func (s *AdminServer) handleListMessages(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	filter := store.MessageFilter{
		Status: strings.TrimSpace(query.Get("status")),
		Limit:  s.pageLimit(r),
	}

	if raw := strings.TrimSpace(query.Get("credential_id")); raw != "" {
		credentialID, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, errorBody{
				Code: codeInvalidRequest, Field: "credential_id",
				Message: "credential_id must be a valid id",
			})
			return
		}
		filter.CredentialID = credentialID
	}

	if raw := strings.TrimSpace(query.Get("cursor")); raw != "" {
		createdAt, id, err := decodeCursor(raw)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, errorBody{
				Code: codeInvalidCursor, Field: "cursor", Message: err.Error(),
			})
			return
		}
		filter.BeforeCreatedAt = createdAt
		filter.BeforeID = id
	}

	rows, err := s.store.ListMessages(r.Context(), filter)
	if err != nil {
		s.writeStoreError(w, "list messages", err)
		return
	}

	out := make([]messageResponseAdmin, 0, len(rows))
	for _, row := range rows {
		out = append(out, newAdminMessageResponse(row))
	}

	response := listResponse[messageResponseAdmin]{Data: out}
	// A cursor is only offered on a full page. Offering one on a short page would
	// have a client fetch an empty page to learn it had finished.
	if int32(len(rows)) == filter.Limit && len(rows) > 0 {
		last := rows[len(rows)-1]
		response.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *AdminServer) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathUUID(w, r, "id")
	if !ok {
		return
	}

	row, err := s.store.GetMessage(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, "get message", err)
		return
	}
	// No payload, ever. An admin sees metadata and delivery status; the message
	// body is not theirs to read, and an endpoint that returned it would make the
	// admin API a mail archive.
	writeJSON(w, http.StatusOK, newAdminMessageDetail(row))
}

// --- helpers ----------------------------------------------------------------

// audit records an administrative change.
//
// Who changed what, at info level, on every mutation. The access log already
// carries the admin's identity; this line carries the intent, which is what makes
// the trail readable months later.
func (s *AdminServer) audit(r *http.Request, action, kind, id, detail string) {
	identity, _ := identityFrom(r.Context())

	attrs := []any{
		slog.String("admin", identity.String()),
		slog.String("admin_role", string(identity.Role)),
		slog.String("resource", kind),
		slog.String("resource_id", id),
	}
	if detail != "" {
		attrs = append(attrs, slog.String("detail", detail))
	}
	if addr := clientIPFrom(r.Context()); addr.IsValid() {
		attrs = append(attrs, slog.String("remote_ip", addr.String()))
	}
	s.log.Info(action, attrs...)
}

// isValidationError reports whether err came from the application's own checks
// rather than from the database.
//
// Every case is a typed sentinel. An earlier version guessed from the error text
// and classified "refusing SMTP AUTH over a plaintext backend connection" as a
// database failure — because the message contains the word "connection" — and
// answered 503 to a request that was simply invalid. Matching on substrings to
// decide 4xx versus 5xx is a bug waiting for the right wording.
func isValidationError(err error) bool {
	return errors.Is(err, store.ErrValidation) ||
		errors.Is(err, frompattern.ErrInvalidPattern) ||
		errors.Is(err, frompattern.ErrInvalidAddress) ||
		errors.Is(err, crypto.ErrMalformedSecret)
}

// credentialField guesses which payload field a credential validation error is
// about, so a UI can place the message.
func credentialField(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "SMTP username"):
		return "username"
	case strings.Contains(message, "credential type"):
		return "type"
	case strings.Contains(message, "name"):
		return "name"
	case strings.Contains(message, "pattern"):
		return "patterns"
	case strings.Contains(message, "rate limit"):
		return "rate_limit_rps"
	default:
		return ""
	}
}
