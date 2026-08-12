package httpapi

import (
	"time"

	dbgen "github.com/amenitydev/relais/internal/db/gen"
	"github.com/amenitydev/relais/internal/store"
)

// Every admin response goes through an explicit type in this file.
//
// The database rows are never serialised directly. That is not style: a
// dbgen.SmtpBackend carries auth_password_sealed and a dbgen.Credential carries
// secret_hmac, and `json.Marshal` on either would put them on the wire. An
// explicit struct means adding a column cannot silently start publishing it.

// backendResponse describes an outbound relay.
type backendResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int32  `json:"port"`

	TLSMode string `json:"tls_mode"`
	// AuthUser is shown; the password never is. There is no field for it, not even
	// a masked one, because a masked field invites a reader to wonder whether some
	// other endpoint returns the real value.
	AuthUser string `json:"auth_user"`
	// HasPassword tells the UI whether a credential is stored, which is all it
	// needs to decide between "set" and "rotate".
	HasPassword bool `json:"has_password"`

	HeloName       string `json:"helo_name"`
	MaxConcurrency int32  `json:"max_concurrency"`
	Enabled        bool   `json:"enabled"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func newBackendResponse(row dbgen.SmtpBackend) backendResponse {
	return backendResponse{
		ID:             row.ID.String(),
		Name:           row.Name,
		Host:           row.Host,
		Port:           row.Port,
		TLSMode:        row.TlsMode,
		AuthUser:       row.AuthUser,
		HasPassword:    row.AuthPasswordSealed != "",
		HeloName:       row.HeloName,
		MaxConcurrency: row.MaxConcurrency,
		Enabled:        row.Enabled,
		CreatedAt:      row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      row.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// domainResponse describes a sending domain.
type domainResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	BackendID   string `json:"backend_id"`
	BackendName string `json:"backend_name,omitempty"`
	// BackendEnabled is surfaced because a domain pointing at a disabled backend
	// delivers nothing, and that state is invisible from the domain alone.
	BackendEnabled *bool `json:"backend_enabled,omitempty"`

	IncludeSubdomains bool `json:"include_subdomains"`
	Enabled           bool `json:"enabled"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func newDomainResponse(row dbgen.Domain) domainResponse {
	return domainResponse{
		ID:                row.ID.String(),
		Name:              row.Name,
		BackendID:         row.SmtpBackendID.String(),
		IncludeSubdomains: row.IncludeSubdomains,
		Enabled:           row.Enabled,
		CreatedAt:         row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:         row.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func newDomainListResponse(row dbgen.ListDomainsRow) domainResponse {
	backendEnabled := row.BackendEnabled
	return domainResponse{
		ID:                row.ID.String(),
		Name:              row.Name,
		BackendID:         row.SmtpBackendID.String(),
		BackendName:       row.BackendName,
		BackendEnabled:    &backendEnabled,
		IncludeSubdomains: row.IncludeSubdomains,
		Enabled:           row.Enabled,
		CreatedAt:         row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:         row.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// credentialResponse describes a sender credential.
//
// It carries no secret and no fingerprint. `lookup` is the public half — an API
// key's prefix or an SMTP username — and is safe to show; it is what an operator
// matches against a client's configuration.
type credentialResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Lookup string `json:"lookup"`

	// State is "active", "disabled" or "revoked": one field the UI can render,
	// rather than two booleans it has to combine correctly.
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`

	RateLimitRPS   *float64 `json:"rate_limit_rps"`
	RateLimitBurst *int32   `json:"rate_limit_burst"`

	// PatternCount is on the list response so the UI can flag a credential that
	// can send as nobody without a second request per row.
	PatternCount int64 `json:"pattern_count"`

	CreatedBy  string  `json:"created_by"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	RevokedAt  *string `json:"revoked_at"`
}

func credentialState(enabled bool, revokedAt *time.Time) string {
	switch {
	case revokedAt != nil:
		return "revoked"
	case !enabled:
		return "disabled"
	default:
		return "active"
	}
}

func newCredentialResponse(row dbgen.Credential, patternCount int64) credentialResponse {
	return credentialResponse{
		ID:             row.ID.String(),
		Name:           row.Name,
		Type:           row.Type,
		Lookup:         row.Lookup,
		State:          credentialState(row.Enabled, row.RevokedAt),
		Enabled:        row.Enabled,
		RateLimitRPS:   row.RateLimitRps,
		RateLimitBurst: row.RateLimitBurst,
		PatternCount:   patternCount,
		CreatedBy:      row.CreatedBy,
		CreatedAt:      row.CreatedAt.UTC().Format(time.RFC3339),
		LastUsedAt:     rfc3339(row.LastUsedAt),
		RevokedAt:      rfc3339(row.RevokedAt),
	}
}

// createdCredentialResponse is returned once, and only once, at creation.
//
// The secret exists nowhere else: relais stores a fingerprint, so no endpoint can
// ever return it again. The Warning field says so in the payload, because a UI
// that loses this modal loses the credential.
type createdCredentialResponse struct {
	Credential credentialResponse `json:"credential"`
	// Secret is the API key or the SMTP password, in the clear, for this one
	// response.
	Secret string `json:"secret"`
	// Username is set for an smtp_user credential, since SMTP AUTH sends it
	// separately from the password.
	Username string   `json:"username,omitempty"`
	Patterns []string `json:"patterns"`
	Warning  string   `json:"warning"`
}

// patternResponse describes one entry of a credential's allow-list.
type patternResponse struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	// Explanation renders the grammar in words, because "*@*.example.com" not
	// covering "example.com" is the single most surprising thing about it.
	Explanation string `json:"explanation"`
	CreatedAt   string `json:"created_at"`
}

func newPatternResponse(row dbgen.CredentialFromPattern) patternResponse {
	return patternResponse{
		ID:          row.ID.String(),
		Pattern:     row.Pattern,
		Explanation: explainPattern(row.Pattern),
		CreatedAt:   row.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// messageResponseAdmin describes a message in the admin views.
//
// It differs from the client-facing messageResponse by naming the credential and
// the backend: an operator is looking across credentials, a client only ever sees
// its own.
type messageResponseAdmin struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Facade string `json:"facade"`

	CredentialID   string `json:"credential_id,omitempty"`
	CredentialName string `json:"credential_name,omitempty"`
	BackendName    string `json:"backend_name,omitempty"`

	From    string   `json:"from"`
	To      []string `json:"to"`
	Cc      []string `json:"cc,omitempty"`
	Bcc     []string `json:"bcc,omitempty"`
	Subject string   `json:"subject"`

	Recipients []string `json:"recipients"`
	MessageID  string   `json:"message_id"`
	SizeBytes  int32    `json:"size_bytes"`
	Attempts   int32    `json:"attempts"`
	RemoteIP   string   `json:"remote_ip,omitempty"`

	CreatedAt string  `json:"created_at"`
	SentAt    *string `json:"sent_at"`

	Error           *messageError `json:"error,omitempty"`
	RejectionReason *string       `json:"rejection_reason,omitempty"`
}

func newAdminMessageResponse(row dbgen.ListEmailMessagesRow) messageResponseAdmin {
	response := messageResponseAdmin{
		ID:              row.ID.String(),
		Status:          row.Status,
		Facade:          row.Facade,
		From:            row.FromAddr,
		To:              row.ToAddrs,
		Cc:              row.CcAddrs,
		Bcc:             row.BccAddrs,
		Subject:         row.Subject,
		Recipients:      row.EnvelopeRecipients,
		MessageID:       row.MessageID,
		SizeBytes:       row.SizeBytes,
		Attempts:        row.AttemptCount,
		CreatedAt:       row.CreatedAt.UTC().Format(time.RFC3339),
		SentAt:          rfc3339(row.SentAt),
		RejectionReason: row.RejectionReason,
	}
	if row.CredentialID != nil {
		response.CredentialID = row.CredentialID.String()
	}
	if row.CredentialName != nil {
		response.CredentialName = *row.CredentialName
	}
	if row.BackendName != nil {
		response.BackendName = *row.BackendName
	}
	if row.RemoteIp != nil {
		response.RemoteIP = row.RemoteIp.String()
	}
	if row.ErrorCode != nil {
		response.Error = &messageError{Code: *row.ErrorCode}
		if row.ErrorDetail != nil {
			response.Error.Detail = *row.ErrorDetail
		}
	}
	return response
}

func newAdminMessageDetail(row dbgen.EmailMessage) messageResponseAdmin {
	response := messageResponseAdmin{
		ID:              row.ID.String(),
		Status:          row.Status,
		Facade:          row.Facade,
		From:            row.FromAddr,
		To:              row.ToAddrs,
		Cc:              row.CcAddrs,
		Bcc:             row.BccAddrs,
		Subject:         row.Subject,
		Recipients:      row.EnvelopeRecipients,
		MessageID:       row.MessageID,
		SizeBytes:       row.SizeBytes,
		Attempts:        row.AttemptCount,
		CreatedAt:       row.CreatedAt.UTC().Format(time.RFC3339),
		SentAt:          rfc3339(row.SentAt),
		RejectionReason: row.RejectionReason,
	}
	if row.CredentialID != nil {
		response.CredentialID = row.CredentialID.String()
	}
	if row.RemoteIp != nil {
		response.RemoteIP = row.RemoteIp.String()
	}
	if row.ErrorCode != nil {
		response.Error = &messageError{Code: *row.ErrorCode}
		if row.ErrorDetail != nil {
			response.Error.Detail = *row.ErrorDetail
		}
	}
	return response
}

// listResponse wraps a page, with the cursor for the next one.
type listResponse[T any] struct {
	Data []T `json:"data"`
	// NextCursor is opaque and absent on the last page. Opaque so a client cannot
	// build one by hand and depend on its shape.
	NextCursor string `json:"next_cursor,omitempty"`
}

// statsResponse is the dashboard payload.
type statsResponse struct {
	// Messages counts rows per status, with every known status present even at
	// zero, so a dashboard does not have to guess which keys might be missing.
	Messages map[string]int64 `json:"messages"`
	Backends int              `json:"backends"`
	Domains  int              `json:"domains"`
	// Credentials counts by state, which is what an operator scans for: a large
	// "revoked" number is normal, a large "disabled" one usually is not.
	Credentials map[string]int `json:"credentials"`
}

// identityResponse tells the frontend who it is talking as.
//
// Without it the UI would have to decode the token to know whether to render write
// controls, and decoding a token in the browser is exactly what the BFF design
// exists to avoid.
type identityResponse struct {
	Subject  string   `json:"subject"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Role     string   `json:"role"`
	CanWrite bool     `json:"can_write"`
	Groups   []string `json:"groups"`
}

// probeResponse reports a backend connection test.
type probeResponse struct {
	OK            bool     `json:"ok"`
	UsedTLS       bool     `json:"used_tls"`
	Authenticated bool     `json:"authenticated"`
	Extensions    []string `json:"extensions,omitempty"`
	// Error is set when the probe failed, with the relay's own words.
	Error *messageError `json:"error,omitempty"`
}

// patternValidationResponse is the dry-run of the grammar.
type patternValidationResponse struct {
	Valid bool `json:"valid"`
	// Normalized is the canonical form that would be stored: lowercase, punycode.
	// Showing it is the point — an operator typing "Exemplé.COM" should see
	// "xn--exempl-gva.com" before saving, not discover it afterwards.
	Normalized  string `json:"normalized,omitempty"`
	Explanation string `json:"explanation,omitempty"`
	Error       string `json:"error,omitempty"`
}

// patternTestResponse answers "would this address be allowed?".
type patternTestResponse struct {
	Address        string   `json:"address"`
	Allowed        bool     `json:"allowed"`
	MatchedPattern string   `json:"matched_pattern,omitempty"`
	Patterns       []string `json:"patterns"`
	// RoutableDomain and BackendName answer the second half of the question. A
	// pattern can allow an address no domain routes, and seeing only "allowed"
	// would send an operator away believing the setup works.
	RoutableDomain bool   `json:"routable_domain"`
	BackendName    string `json:"backend_name,omitempty"`
}

func newPatternTestResponse(result store.PatternTestResult) patternTestResponse {
	patterns := result.Patterns
	if patterns == nil {
		patterns = []string{}
	}
	return patternTestResponse{
		Address:        result.Address,
		Allowed:        result.Allowed,
		MatchedPattern: result.MatchedPattern,
		Patterns:       patterns,
		RoutableDomain: result.RoutableDomain,
		BackendName:    result.BackendName,
	}
}

// resolveResponse reports which backend would carry a sender's mail.
type resolveResponse struct {
	Sender     string `json:"sender"`
	Resolved   bool   `json:"resolved"`
	DomainName string `json:"domain_name,omitempty"`
	BackendID  string `json:"backend_id,omitempty"`
	Backend    string `json:"backend_name,omitempty"`
	Address    string `json:"backend_address,omitempty"`
	TLSMode    string `json:"tls_mode,omitempty"`
	UsesAuth   bool   `json:"uses_auth"`
	// Reason explains a failure to resolve, which is nearly always a missing
	// include_subdomains.
	Reason string `json:"reason,omitempty"`
}
