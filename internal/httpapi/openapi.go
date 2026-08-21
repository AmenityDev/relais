package httpapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// This file emits the OpenAPI documents from the Go types that actually serve the
// requests, rather than from a hand-written specification alongside them.
//
// The reason is the same one that keeps the sender-pattern grammar out of
// TypeScript: a second description of the same thing drifts, and the day it
// drifts it lies. A hand-written schema that still lists a field the handler
// stopped returning generates a TypeScript type an operator's build accepts and
// the runtime does not. So the schemas below are read off the request and
// response structs by reflection, the route table names those structs by
// identity (a renamed type stops compiling), and CI diffs the committed document
// against a fresh one exactly as it diffs the sqlc output.
//
// What is NOT derived: which fields a POST requires, and the operation prose.
// Neither is recoverable from a struct — the same backendRequest serves a
// create, where a host is mandatory, and a patch, where every field is optional.
// Those live in the table, and a test asserts every name in them exists in the
// generated schema, so they cannot drift either.

// OpenAPIVersion is the spec version emitted. 3.1 rather than 3.0 because it is
// aligned with JSON Schema, which is what makes a nullable field expressible as
// a type union instead of 3.0's proprietary `nullable` keyword.
const OpenAPIVersion = "3.1.0"

// APIVersion is the version of the HTTP contract, which is what OpenAPI's
// info.version means. It tracks the /v1 in the paths, not the binary: a document
// stamped with the build version would differ from a fresh one on every tagged
// build, and CI's comparison would become noise.
const APIVersion = "v1"

// Surface identifies which document to emit. The two listeners are separate on
// purpose (F11), and merging them into one document would blur the boundary that
// separation exists to draw: a reader of the public document must not be able to
// mistake an admin endpoint for something their API key can reach.
type Surface string

const (
	// SurfaceAdmin is the operator API behind OIDC, on the admin listener.
	SurfaceAdmin Surface = "admin"
	// SurfacePublic is the sending API behind an API key, on the public listener.
	SurfacePublic Surface = "public"
)

// apiParam is a path or query parameter.
type apiParam struct {
	Name        string
	In          string // "path" or "query"
	Description string
	Required    bool
	Type        string // "string" or "integer"
	Format      string
	Enum        []string
}

// apiOperation is one route. Request and Response hold a zero value of the
// struct that the handler decodes and encodes, so the schema is read from the
// type the code actually uses.
type apiOperation struct {
	Method  string
	Path    string
	ID      string
	Summary string
	Notes   string
	Params  []apiParam

	// Request is a zero value of the decoded body, nil when there is none.
	Request any
	// RequestSchema names the component this body is published as.
	//
	// Named per operation rather than per Go type, because one struct serves both
	// a create and a patch and those are not the same contract: BackendInput
	// demands a host, BackendPatch changes only what it mentions. Emitting one
	// schema for both would tell a TypeScript consumer that a patch must resend
	// every field, or that a create may omit them all. Both are wrong.
	RequestSchema string
	// RequiredFields lists the body fields this operation rejects when absent.
	// Not derivable from the struct: see the note at the top of this file.
	RequiredFields []string

	// Response is a zero value of the success body, nil for 204.
	Response any
	Status   int

	// Write marks an operation the editor role gates. Read off the router by the
	// test rather than trusted from here.
	Write bool

	// Errors lists the documented failure statuses beyond the defaults every
	// operation shares.
	Errors []int
}

// schemaNames maps a Go type to its public schema name.
//
// Explicit rather than derived from the Go identifier, because the generated
// TypeScript is a published interface: renaming `messageResponseAdmin` in Go is
// an internal tidy-up and must not rename `Message` in a consumer's build.
var schemaNames = map[reflect.Type]string{
	reflect.TypeOf(backendResponse{}):           "Backend",
	reflect.TypeOf(domainResponse{}):            "Domain",
	reflect.TypeOf(credentialResponse{}):        "Credential",
	reflect.TypeOf(createdCredentialResponse{}): "CreatedCredential",
	reflect.TypeOf(patternResponse{}):           "Pattern",
	reflect.TypeOf(messageResponseAdmin{}):      "Message",
	reflect.TypeOf(messageResponse{}):           "SentMessage",
	reflect.TypeOf(messageError{}):              "MessageError",
	reflect.TypeOf(statsResponse{}):             "Stats",
	reflect.TypeOf(identityResponse{}):          "Identity",
	reflect.TypeOf(probeResponse{}):             "ProbeResult",
	reflect.TypeOf(patternValidationResponse{}): "PatternValidation",
	reflect.TypeOf(patternTestResponse{}):       "PatternTest",
	reflect.TypeOf(resolveResponse{}):           "ResolveResult",
	// errorEnvelope, not errorBody: writeError wraps every error as
	// {"error": {...}}. Naming the inner type here described a shape the server never
	// sends, and the generated TypeScript then read `code` off the envelope and found
	// nothing — so every API error reached the operator as a bare status code. Caught
	// by sending a real 422 through the interface, not by any test.
	reflect.TypeOf(errorEnvelope{}):     "Error",
	reflect.TypeOf(errorBody{}):         "ErrorDetail",
	reflect.TypeOf(sendResponse{}):      "SendResult",
	reflect.TypeOf(requestAttachment{}): "Attachment",

	reflect.TypeOf(listResponse[backendResponse]{}):      "BackendList",
	reflect.TypeOf(listResponse[domainResponse]{}):       "DomainList",
	reflect.TypeOf(listResponse[credentialResponse]{}):   "CredentialList",
	reflect.TypeOf(listResponse[patternResponse]{}):      "PatternList",
	reflect.TypeOf(listResponse[messageResponseAdmin]{}): "MessageList",
}

// customSchemas overrides reflection for types whose JSON representation is not
// their Go shape.
//
// A type with its own UnmarshalJSON accepts something reflection cannot see.
// addressList is a []string that also accepts a bare string; emitted from its Go
// shape alone, the generated TypeScript would reject a payload the API accepts.
// openAPITestCustomTypesAreDeclared asserts every json.Unmarshaler appears here,
// so the next such type cannot slip through with a wrong schema.
var customSchemas = map[reflect.Type]map[string]any{
	reflect.TypeOf(addressList{}): {
		"description": "One address, or a list of them.",
		"oneOf": []any{
			map[string]any{"type": "string"},
			map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	},
}

// adminOperations describes the operator API.
func adminOperations() []apiOperation {
	idParam := apiParam{
		Name: "id", In: "path", Required: true, Type: "string", Format: "uuid",
	}
	pagination := []apiParam{
		{Name: "limit", In: "query", Type: "integer", Description: "Page size."},
		{
			Name: "cursor", In: "query", Type: "string",
			Description: "Opaque cursor from a previous response's next_cursor. " +
				"Opaque so a client cannot build one by hand and then depend on its shape.",
		},
	}

	return []apiOperation{
		{
			Method: "GET", Path: "/admin/v1/identity", ID: "getIdentity",
			Summary: "Who the caller is acting as",
			Notes: "The frontend renders write controls from this rather than by decoding " +
				"the token, which is what the BFF design exists to avoid.",
			Response: identityResponse{}, Status: 200,
		},
		{
			Method: "GET", Path: "/admin/v1/stats", ID: "getStats",
			Summary:  "Dashboard counters",
			Response: statsResponse{}, Status: 200,
		},

		{
			Method: "GET", Path: "/admin/v1/backends", ID: "listBackends",
			Summary:  "List the SMTP relays mail is handed to",
			Response: listResponse[backendResponse]{}, Status: 200,
		},
		{
			Method: "POST", Path: "/admin/v1/backends", ID: "createBackend",
			Summary:        "Register a relay",
			Request:        backendRequest{},
			RequestSchema:  "BackendInput",
			RequiredFields: []string{"name", "host", "port", "tls_mode"},
			Response:       backendResponse{}, Status: 201,
			Write: true, Errors: []int{409, 422},
		},
		{
			Method: "PATCH", Path: "/admin/v1/backends/{id}", ID: "updateBackend",
			Summary: "Update a relay",
			Notes: "Absent fields are left as they are. Sending `password` replaces the " +
				"sealed value; there is no way to read the current one back.",
			Params: []apiParam{idParam}, Request: backendRequest{},
			RequestSchema: "BackendPatch",
			Response:      backendResponse{}, Status: 200,
			Write: true, Errors: []int{404, 409, 422},
		},
		{
			Method: "DELETE", Path: "/admin/v1/backends/{id}", ID: "deleteBackend",
			Summary: "Remove a relay",
			Notes:   "Refused with 409 while a domain still points at it.",
			Params:  []apiParam{idParam}, Status: 204,
			Write: true, Errors: []int{404, 409},
		},
		{
			Method: "POST", Path: "/admin/v1/backends/{id}:test", ID: "probeBackend",
			Summary: "Open a connection to the relay and authenticate",
			Notes: "Counts as a write: it acts outside relais using stored credentials. " +
				"Returns 200 with ok=false when the relay refuses, since the probe " +
				"itself succeeded in finding that out.",
			Params:   []apiParam{idParam},
			Response: probeResponse{}, Status: 200,
			Write: true, Errors: []int{404},
		},

		{
			Method: "GET", Path: "/admin/v1/domains", ID: "listDomains",
			Summary: "List the sending domains and where each routes",
			Notes: "Carries backend_enabled: a domain pointing at a disabled relay " +
				"delivers nothing, and the UI must be able to say so.",
			Response: listResponse[domainResponse]{}, Status: 200,
		},
		{
			Method: "POST", Path: "/admin/v1/domains", ID: "createDomain",
			Summary:        "Add a sending domain",
			Request:        domainRequest{},
			RequestSchema:  "DomainInput",
			RequiredFields: []string{"name", "backend_id"},
			Response:       domainResponse{}, Status: 201,
			Write: true, Errors: []int{409, 422},
		},
		{
			Method: "PATCH", Path: "/admin/v1/domains/{id}", ID: "updateDomain",
			Summary: "Update a sending domain",
			Params:  []apiParam{idParam}, Request: domainRequest{},
			RequestSchema: "DomainPatch",
			Response:      domainResponse{}, Status: 200,
			Write: true, Errors: []int{404, 409, 422},
		},
		{
			Method: "DELETE", Path: "/admin/v1/domains/{id}", ID: "deleteDomain",
			Summary: "Remove a sending domain",
			Params:  []apiParam{idParam}, Status: 204,
			Write: true, Errors: []int{404, 409},
		},
		{
			Method: "GET", Path: "/admin/v1/domains:resolve", ID: "resolveDomain",
			Summary: "Which relay would carry this sender's mail",
			Notes: "A dry run. It answers the question a failing configuration actually " +
				"poses, which is nearly always a missing include_subdomains.",
			Params: []apiParam{{
				Name: "sender", In: "query", Required: true, Type: "string",
				Description: "An email address.",
			}},
			Response: resolveResponse{}, Status: 200,
			Errors: []int{422},
		},

		{
			Method: "GET", Path: "/admin/v1/credentials", ID: "listCredentials",
			Summary: "List the sending credentials",
			Notes: "pattern_count is zero for a credential that can send as nobody. " +
				"That is a misconfiguration, not a default, and deserves a badge.",
			Response: listResponse[credentialResponse]{}, Status: 200,
		},
		{
			Method: "POST", Path: "/admin/v1/credentials", ID: "createCredential",
			Summary: "Create a credential",
			Notes: "The only response that ever carries the secret in the clear. relais " +
				"stores a peppered HMAC and cannot show it again, so a client that " +
				"loses this response has to issue a new credential.",
			Request:        createCredentialRequest{},
			RequestSchema:  "CreateCredentialInput",
			RequiredFields: []string{"name", "type"},
			Response:       createdCredentialResponse{}, Status: 201,
			Write: true, Errors: []int{409, 422},
		},
		{
			Method: "GET", Path: "/admin/v1/credentials/{id}", ID: "getCredential",
			Summary:  "Fetch one credential",
			Params:   []apiParam{idParam},
			Response: credentialResponse{}, Status: 200,
			Errors: []int{404},
		},
		{
			Method: "PATCH", Path: "/admin/v1/credentials/{id}", ID: "updateCredential",
			Summary: "Update a credential",
			Params:  []apiParam{idParam}, Request: updateCredentialRequest{},
			RequestSchema: "CredentialPatch",
			Response:      credentialResponse{}, Status: 200,
			Write: true, Errors: []int{404, 422},
		},
		{
			Method: "POST", Path: "/admin/v1/credentials/{id}:revoke", ID: "revokeCredential",
			Summary: "Revoke a credential",
			Notes: "Irreversible, and deliberately not a delete: the messages it sent " +
				"keep pointing at it, which is what makes an audit possible.",
			Params:   []apiParam{idParam},
			Response: credentialResponse{}, Status: 200,
			Write: true, Errors: []int{404},
		},
		{
			Method: "POST", Path: "/admin/v1/credentials/{id}:rotate", ID: "rotateCredential",
			Summary: "Issue a new secret for a credential",
			Notes: "The old secret stops working immediately. Everything else survives: " +
				"the id, the name, the limits and the allow-list, so past messages " +
				"keep their attribution. An smtp_user keeps its username and gets a " +
				"new password; an api_key gets an entirely new token, because the " +
				"lookup is part of the token. Answers 422 for a revoked credential: " +
				"revocation is permanent. Like creation, this is a response that " +
				"carries the secret once and cannot be replayed.",
			Params:   []apiParam{idParam},
			Response: createdCredentialResponse{}, Status: 200,
			Write: true, Errors: []int{404, 422},
		},
		{
			Method: "DELETE", Path: "/admin/v1/credentials/{id}", ID: "deleteCredential",
			Summary: "Remove a credential",
			Notes: "Heavier than revoking, not stronger. The messages this credential " +
				"sent survive but stop naming it, so the audit trail loses who " +
				"submitted them; revoke is still the answer to a leaked secret.",
			Params: []apiParam{idParam}, Status: 204,
			Write: true, Errors: []int{404},
		},

		{
			Method: "GET", Path: "/admin/v1/credentials/{id}/patterns", ID: "listPatterns",
			Summary:  "The addresses this credential may send as",
			Params:   []apiParam{idParam},
			Response: listResponse[patternResponse]{}, Status: 200,
			Errors: []int{404},
		},
		{
			Method: "POST", Path: "/admin/v1/credentials/{id}/patterns", ID: "addPatterns",
			Summary: "Allow more addresses",
			Params:  []apiParam{idParam}, Request: addPatternsRequest{},
			RequestSchema:  "AddPatternsInput",
			RequiredFields: []string{"patterns"},
			Response:       listResponse[patternResponse]{}, Status: 201,
			Write: true, Errors: []int{404, 422},
		},
		{
			Method: "DELETE", Path: "/admin/v1/credentials/{id}/patterns/{patternID}",
			ID: "deletePattern", Summary: "Withdraw an allowed address",
			Params: []apiParam{idParam, {
				Name: "patternID", In: "path", Required: true, Type: "string", Format: "uuid",
			}},
			Status: 204, Write: true, Errors: []int{404},
		},
		{
			Method: "POST", Path: "/admin/v1/patterns:validate", ID: "validatePattern",
			Summary: "Check a pattern and show its canonical form",
			Notes: "A dry run against the real grammar, which is why the frontend never " +
				"reimplements it. Returns 200 with valid=false for a bad pattern: " +
				"the question was answered.",
			Request: validatePatternRequest{}, RequiredFields: []string{"pattern"},
			RequestSchema: "ValidatePatternInput",
			Response:      patternValidationResponse{}, Status: 200,
		},
		{
			Method: "POST", Path: "/admin/v1/credentials/{id}/patterns:test", ID: "testPattern",
			Summary: "Would this credential be allowed to send as this address",
			Notes: "Also answers whether any enabled domain routes that sender. A pattern " +
				"can allow an address nothing routes, and seeing only \"allowed\" " +
				"would send an operator away believing the setup works.",
			Params: []apiParam{idParam}, Request: testPatternRequest{},
			RequestSchema:  "TestPatternInput",
			RequiredFields: []string{"address"},
			Response:       patternTestResponse{}, Status: 200,
			Errors: []int{404, 422},
		},

		{
			Method: "GET", Path: "/admin/v1/messages", ID: "listMessages",
			Summary: "The message log, newest first",
			Params: append([]apiParam{
				{
					Name: "status", In: "query", Type: "string",
					Enum: []string{"queued", "sending", "sent", "failed", "rejected", "partial"},
				},
				{Name: "credential_id", In: "query", Type: "string", Format: "uuid"},
			}, pagination...),
			Response: listResponse[messageResponseAdmin]{}, Status: 200,
			Errors: []int{422},
		},
		{
			Method: "GET", Path: "/admin/v1/messages/{id}", ID: "getMessage",
			Summary: "One message, with the relay's own error",
			Notes: "Never the body. Content is held only until delivery and is returned " +
				"by no endpoint.",
			Params:   []apiParam{idParam},
			Response: messageResponseAdmin{}, Status: 200,
			Errors: []int{404},
		},
	}
}

// publicOperations describes the sending API.
func publicOperations() []apiOperation {
	return []apiOperation{
		{
			Method: "POST", Path: "/v1/emails", ID: "sendEmail",
			Summary: "Submit a message for relaying",
			Notes: "Accepted means queued, not delivered. Send an Idempotency-Key header " +
				"to make a retry safe: the same key returns the first result with " +
				"idempotent_replay set, rather than sending twice.",
			Request: sendRequest{}, RequiredFields: []string{"from"},
			RequestSchema: "SendInput",
			Response:      sendResponse{}, Status: 202,
			Errors: []int{403, 422, 429},
		},
		{
			Method: "GET", Path: "/v1/emails/{id}", ID: "getEmail",
			Summary: "The status of a message you submitted",
			Notes:   "Scoped to the calling credential: another credential's message is a 404.",
			Params: []apiParam{{
				Name: "id", In: "path", Required: true, Type: "string", Format: "uuid",
			}},
			Response: messageResponse{}, Status: 200,
			Errors: []int{404},
		},
	}
}

// operationsFor returns the table for a surface.
func operationsFor(surface Surface) ([]apiOperation, error) {
	switch surface {
	case SurfaceAdmin:
		return adminOperations(), nil
	case SurfacePublic:
		return publicOperations(), nil
	default:
		return nil, fmt.Errorf("unknown surface %q: want %q or %q", surface, SurfaceAdmin, SurfacePublic)
	}
}

// OpenAPI renders the document for a surface as indented JSON.
//
// JSON rather than YAML so that the committed file can be diffed byte for byte
// without a YAML library's formatting choices entering into it.
func OpenAPI(surface Surface, version string) ([]byte, error) {
	ops, err := operationsFor(surface)
	if err != nil {
		return nil, err
	}

	gen := &schemaBuilder{
		schemas:       map[string]any{},
		kinds:         map[string]schemaKind{},
		requestOrigin: map[string]requestProvenance{},
	}
	paths := map[string]any{}

	for _, op := range ops {
		item, _ := paths[op.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[op.Path] = item
		}
		rendered, err := gen.operation(op)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
		}
		method := strings.ToLower(op.Method)
		if _, clash := item[method]; clash {
			return nil, fmt.Errorf("duplicate operation %s %s", op.Method, op.Path)
		}
		item[method] = rendered
	}

	// Every operation can fail this way, so documenting it per operation would be
	// noise that hides the ones that differ.
	if _, err := gen.ref(reflect.TypeOf(errorEnvelope{}), kindResponse); err != nil {
		return nil, err
	}

	doc := map[string]any{
		"openapi": OpenAPIVersion,
		"info": map[string]any{
			"title":       surfaceTitle(surface),
			"version":     version,
			"description": surfaceDescription(surface),
		},
		"servers":    surfaceServers(surface),
		"paths":      paths,
		"components": gen.components(surface),
	}
	if surface == SurfaceAdmin {
		doc["security"] = []any{map[string]any{"oidc": []any{}}}
	} else {
		doc["security"] = []any{map[string]any{"apiKey": []any{}}}
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func surfaceTitle(surface Surface) string {
	if surface == SurfaceAdmin {
		return "relais admin API"
	}
	return "relais sending API"
}

func surfaceDescription(surface Surface) string {
	if surface == SurfaceAdmin {
		return "The operator API: relays, sending domains, credentials and their " +
			"sender allow-lists, and the message log.\n\n" +
			"Served on the admin listener (RELAIS_ADMIN_ADDR, default :8081), which is " +
			"separate from the sending listener so that exposing one is a network " +
			"decision rather than a routing rule nobody must get wrong. It is not " +
			"intended to be reachable from a browser.\n\n" +
			"Generated from the Go types that serve the requests. Do not edit by hand."
	}
	return "The sending API, equivalent to the SMTP submission façade: both converge " +
		"on one pipeline, so a message is authorised the same way whichever it " +
		"arrived through.\n\n" +
		"Every request must be authenticated; there is no anonymous relaying under " +
		"any condition.\n\n" +
		"Generated from the Go types that serve the requests. Do not edit by hand."
}

func surfaceServers(surface Surface) []any {
	if surface == SurfaceAdmin {
		return []any{map[string]any{
			"url":         "http://localhost:8081",
			"description": "The admin listener.",
		}}
	}
	return []any{map[string]any{
		"url":         "http://localhost:8080",
		"description": "The sending listener.",
	}}
}

// schemaKind distinguishes a body the client sends from one the server returns.
//
// It decides what "required" means. In a response it is a promise: the server
// always emits this key, so a consumer need not test for it. In a request it is a
// demand, and the demand belongs to the operation rather than to the struct — the
// same fields that a create requires, a patch leaves alone.
type schemaKind int

const (
	kindResponse schemaKind = iota
	kindRequest
)

// schemaBuilder accumulates the component schemas as operations reference them.
type schemaBuilder struct {
	schemas map[string]any
	// kinds records how each named schema was generated, so a type used as both a
	// request and a response is reported instead of silently taking whichever
	// meaning was built first.
	kinds map[string]schemaKind
	// requestOrigin records the Go type and required list behind each request
	// schema name, so two operations cannot publish the same name with different
	// contracts.
	requestOrigin map[string]requestProvenance
}

type requestProvenance struct {
	typ      reflect.Type
	required []string
}

func (b *schemaBuilder) components(surface Surface) map[string]any {
	schemes := map[string]any{}
	if surface == SurfaceAdmin {
		schemes["oidc"] = map[string]any{
			"type":         "http",
			"scheme":       "bearer",
			"bearerFormat": "JWT",
			"description": "An access token from the configured OIDC issuer. The group claim " +
				"decides the role; Go is the authority on that, never the caller.",
		}
	} else {
		schemes["apiKey"] = map[string]any{
			"type":   "http",
			"scheme": "bearer",
			"description": "A credential secret, shown once at creation. relais stores only a " +
				"peppered HMAC of it.",
		}
	}
	return map[string]any{
		"schemas":         b.schemas,
		"securitySchemes": schemes,
	}
}

// operation renders one route.
func (b *schemaBuilder) operation(op apiOperation) (map[string]any, error) {
	out := map[string]any{
		"operationId": op.ID,
		"summary":     op.Summary,
	}
	if op.Notes != "" {
		out["description"] = op.Notes
	}

	if len(op.Params) > 0 {
		params := make([]any, 0, len(op.Params))
		for _, p := range op.Params {
			schema := map[string]any{"type": p.Type}
			if p.Format != "" {
				schema["format"] = p.Format
			}
			if len(p.Enum) > 0 {
				schema["enum"] = toAny(p.Enum)
			}
			rendered := map[string]any{
				"name":     p.Name,
				"in":       p.In,
				"required": p.Required,
				"schema":   schema,
			}
			if p.Description != "" {
				rendered["description"] = p.Description
			}
			params = append(params, rendered)
		}
		out["parameters"] = params
	}

	if op.Request != nil {
		schema, err := b.requestRef(op.RequestSchema, reflect.TypeOf(op.Request), op.RequiredFields)
		if err != nil {
			return nil, err
		}
		out["requestBody"] = map[string]any{
			"required": true,
			"content":  map[string]any{"application/json": map[string]any{"schema": schema}},
		}
	} else if len(op.RequiredFields) > 0 {
		return nil, fmt.Errorf("RequiredFields set on an operation with no request body")
	} else if op.RequestSchema != "" {
		return nil, fmt.Errorf("RequestSchema set on an operation with no request body")
	}

	responses := map[string]any{}
	statusKey := fmt.Sprintf("%d", op.Status)
	if op.Response != nil {
		schema, err := b.ref(reflect.TypeOf(op.Response), kindResponse)
		if err != nil {
			return nil, err
		}
		responses[statusKey] = map[string]any{
			"description": "Success.",
			"content":     map[string]any{"application/json": map[string]any{"schema": schema}},
		}
	} else {
		responses[statusKey] = map[string]any{"description": "Success, with no body."}
	}

	// The statuses every operation shares, including the 403 a viewer gets from a
	// write. Listing them once here rather than in each table entry keeps the
	// table about what differs.
	statuses := append([]int{401, 403}, op.Errors...)
	// Any operation that decodes a body can be handed malformed JSON, which is a 400
	// rather than the 422 an unacceptable-but-well-formed body gets. Derived from the
	// presence of a request body instead of repeated in the table, so it cannot be
	// forgotten on a new operation.
	if op.Request != nil {
		statuses = append(statuses, 400)
	}
	seen := map[int]bool{}
	for _, code := range statuses {
		if seen[code] {
			continue
		}
		seen[code] = true
		responses[fmt.Sprintf("%d", code)] = map[string]any{
			"description": statusDescription(code),
			"content": map[string]any{"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/Error"},
			}},
		}
	}
	out["responses"] = responses

	if op.Write {
		out["x-relais-requires-write"] = true
	}
	return out, nil
}

func statusDescription(code int) string {
	switch code {
	case 400:
		return "The body is not valid JSON."
	case 401:
		return "No credential, or one that is not valid."
	case 403:
		return "Authenticated, but not allowed to do this."
	case 404:
		return "No such thing, or not yours."
	case 409:
		return "Conflicts with something that already exists, or is still referenced."
	case 422:
		return "The request was understood and is not acceptable."
	case 429:
		return "Rate limited."
	case 503:
		return "A dependency is unavailable. Retry."
	default:
		return "Error."
	}
}

// requestRef generates (once) and references the schema for a request body.
//
// The name comes from the operation, not from the Go type, so the same struct can
// be published as a strict create and a lenient patch. Two operations reusing one
// name must agree on both the type and the required list, or the second is a
// mistake that would otherwise overwrite the first.
func (b *schemaBuilder) requestRef(name string, t reflect.Type, required []string) (map[string]any, error) {
	if name == "" {
		return nil, fmt.Errorf("operation has a request body but no RequestSchema name")
	}
	if prior, seen := b.requestOrigin[name]; seen {
		if prior.typ != t {
			return nil, fmt.Errorf("request schema %s is generated from %s and from %s", name, prior.typ, t)
		}
		if !sameStrings(toAny(prior.required), required) {
			return nil, fmt.Errorf("request schema %s is published with two different required lists", name)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}, nil
	}
	if kind, clash := b.kinds[name]; clash && kind == kindResponse {
		return nil, fmt.Errorf("schema name %s is already used by a response", name)
	}

	schema, err := b.structSchema(t, kindRequest)
	if err != nil {
		return nil, err
	}
	props, _ := schema["properties"].(map[string]any)
	for _, f := range required {
		if _, exists := props[f]; !exists {
			return nil, fmt.Errorf("schema %s has no field %q: the route table names a field the struct does not have", name, f)
		}
	}
	if len(required) > 0 {
		sorted := append([]string(nil), required...)
		sort.Strings(sorted)
		schema["required"] = toAny(sorted)
	}

	b.schemas[name] = schema
	b.kinds[name] = kindRequest
	b.requestOrigin[name] = requestProvenance{typ: t, required: required}
	return map[string]any{"$ref": "#/components/schemas/" + name}, nil
}

// ref returns a reference to a named schema, generating it on first sight.
func (b *schemaBuilder) ref(t reflect.Type, kind schemaKind) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	name, ok := schemaNames[t]
	if !ok {
		return nil, fmt.Errorf("no schema name registered for %s: add it to schemaNames", t)
	}
	if prior, done := b.kinds[name]; done {
		if prior != kind {
			return nil, fmt.Errorf("schema %s is used as both a request and a response: "+
				"split the type, because required means different things in each", name)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}, nil
	}
	// Reserve the name before walking the fields, so a self-referencing type
	// terminates instead of recursing forever.
	b.kinds[name] = kind
	b.schemas[name] = map[string]any{}
	schema, err := b.structSchema(t, kind)
	if err != nil {
		return nil, err
	}
	b.schemas[name] = schema
	return map[string]any{"$ref": "#/components/schemas/" + name}, nil
}

func (b *schemaBuilder) structSchema(t reflect.Type, kind schemaKind) (map[string]any, error) {
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s is not a struct", t)
	}

	props := map[string]any{}
	var required []string

	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = field.Name
		}
		optional := false
		for _, opt := range parts[1:] {
			if opt == "omitempty" {
				optional = true
			}
		}

		schema, err := b.fieldSchema(field.Type, kind)
		if err != nil {
			return nil, fmt.Errorf("field %s.%s: %w", t.Name(), field.Name, err)
		}
		props[name] = schema

		// A pointer field without omitempty is always present and may be null; it
		// is required in the sense OpenAPI means, which is "the key is there".
		if !optional {
			required = append(required, name)
		}
	}

	out := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	// A request's required list belongs to the operation, and requestRef sets it.
	if kind == kindResponse && len(required) > 0 {
		sort.Strings(required)
		out["required"] = toAny(required)
	}
	return out, nil
}

// fieldSchema renders one field's type.
func (b *schemaBuilder) fieldSchema(t reflect.Type, kind schemaKind) (map[string]any, error) {
	// A custom JSON representation wins over the Go shape.
	if custom, ok := customSchemas[t]; ok {
		return cloneSchema(custom), nil
	}

	nullable := false
	for t.Kind() == reflect.Pointer {
		nullable = true
		t = t.Elem()
	}
	if custom, ok := customSchemas[t]; ok {
		return cloneSchema(custom), nil
	}

	var schema map[string]any
	switch t.Kind() {
	case reflect.String:
		schema = map[string]any{"type": "string"}
	case reflect.Bool:
		schema = map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		schema = map[string]any{"type": "integer"}
		if t.Kind() == reflect.Int32 {
			schema["format"] = "int32"
		} else if t.Kind() == reflect.Int64 || t.Kind() == reflect.Int {
			schema["format"] = "int64"
		}
	case reflect.Float32, reflect.Float64:
		schema = map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		items, err := b.fieldSchema(t.Elem(), kind)
		if err != nil {
			return nil, err
		}
		schema = map[string]any{"type": "array", "items": items}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("map key must be a string, got %s", t.Key())
		}
		values, err := b.fieldSchema(t.Elem(), kind)
		if err != nil {
			return nil, err
		}
		schema = map[string]any{"type": "object", "additionalProperties": values}
	case reflect.Struct:
		ref, err := b.ref(t, kind)
		if err != nil {
			return nil, err
		}
		if nullable {
			// A $ref cannot carry a sibling type, so a nullable struct is a union.
			return map[string]any{"oneOf": []any{
				ref, map[string]any{"type": "null"},
			}}, nil
		}
		return ref, nil
	default:
		return nil, fmt.Errorf("unsupported kind %s", t.Kind())
	}

	if nullable {
		schema["type"] = []any{schema["type"], "null"}
	}
	return schema, nil
}

func cloneSchema(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func sameStrings(existing []any, want []string) bool {
	if len(existing) != len(want) {
		return false
	}
	set := map[string]bool{}
	for _, v := range existing {
		s, _ := v.(string)
		set[s] = true
	}
	for _, v := range want {
		if !set[v] {
			return false
		}
	}
	return true
}
