package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/amenitydev/relais/internal/adminauth"
	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/store"
)

// These tests exist because a generated document is only trustworthy if something
// checks that it still describes the server. The generator reads the schemas off
// the real structs, which closes one drift channel; these close the rest.

// routerOperations walks a chi router and returns "METHOD /path" for every route,
// which is the server's own account of what it serves.
func routerOperations(t *testing.T, handler http.Handler) map[string]bool {
	t.Helper()

	mux, ok := handler.(chi.Routes)
	if !ok {
		t.Fatalf("handler is %T, which cannot be walked", handler)
	}

	found := map[string]bool{}
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// chi reports a trailing slash on subrouter mounts; the routes themselves
		// carry none.
		route = strings.TrimSuffix(route, "/")
		if route == "" {
			route = "/"
		}
		found[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	return found
}

// tableOperations is the same account, taken from the route table.
func tableOperations(t *testing.T, surface Surface) map[string]apiOperation {
	t.Helper()

	ops, err := operationsFor(surface)
	if err != nil {
		t.Fatalf("operationsFor: %v", err)
	}
	out := map[string]apiOperation{}
	for _, op := range ops {
		key := op.Method + " " + op.Path
		if _, dup := out[key]; dup {
			t.Fatalf("the route table lists %s twice", key)
		}
		out[key] = op
	}
	return out
}

// adminRouterForWalk builds the admin router without a database.
//
// Handler() only assembles routes, so a zero store is enough: this test is about
// the shape of the router, and requiring Postgres to check a route list would
// make the check skippable exactly when it matters.
func adminRouterForWalk(t *testing.T) http.Handler {
	t.Helper()

	log := slog.New(slog.DiscardHandler)
	verifier, err := adminauth.New(adminauth.Config{
		Issuer:      "https://issuer.invalid",
		Audience:    "relais",
		GroupsClaim: "groups",
		AdminGroup:  "relais-admin",
		ViewerGroup: "relais-viewer",
	}, log)
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}

	server, err := NewAdminServer(AdminOptions{
		Store: &store.Store{}, Verifier: verifier, Pool: &db.Pool{}, Log: log,
		Version: "test", PageSize: 25, MaxPageSize: 100, MaxRequestBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewAdminServer: %v", err)
	}
	return server.Handler()
}

// TestOpenAPIAdminCoversEveryRoute is the check that matters most: a route added
// to the router without an entry in the table would be undocumented, and the
// frontend's generated types would not know it exists.
func TestOpenAPIAdminCoversEveryRoute(t *testing.T) {
	router := routerOperations(t, adminRouterForWalk(t))
	table := tableOperations(t, SurfaceAdmin)

	// Health probes are mounted on both listeners and are deliberately outside the
	// documented API: they carry no schema and answer before authentication.
	skip := map[string]bool{"GET /healthz": true, "GET /readyz": true}

	for key := range router {
		if skip[key] {
			continue
		}
		if _, documented := table[key]; !documented {
			t.Errorf("the router serves %s but the OpenAPI route table does not list it", key)
		}
	}
	for key := range table {
		if !router[key] {
			t.Errorf("the OpenAPI route table lists %s but the router does not serve it", key)
		}
	}
}

// TestOpenAPIWriteFlagsMatchTheRouter pins the write flags against the middleware
// that enforces them.
//
// The flag drives "x-relais-requires-write", which is how the frontend decides
// whether to render a control for a viewer. A flag that disagrees with the router
// would either hide a button that works or offer one that returns 403.
func TestOpenAPIWriteFlagsMatchTheRouter(t *testing.T) {
	handler := adminRouterForWalk(t)
	mux, ok := handler.(chi.Routes)
	if !ok {
		t.Fatalf("handler is %T", handler)
	}

	// requireWrite is a method value, so identity comparison is not available.
	// Counting middlewares is enough to tell the guarded group from the rest: the
	// write group adds exactly one.
	depth := map[string]int{}
	err := chi.Walk(mux, func(method, route string, _ http.Handler, mw ...func(http.Handler) http.Handler) error {
		depth[method+" "+strings.TrimSuffix(route, "/")] = len(mw)
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}

	readDepth, writeDepth := -1, -1
	for key, n := range depth {
		op, documented := tableOperations(t, SurfaceAdmin)[key]
		if !documented {
			continue
		}
		if op.Write {
			if writeDepth == -1 {
				writeDepth = n
			} else if n != writeDepth {
				t.Errorf("%s: write operations do not share a middleware depth (%d vs %d)", key, n, writeDepth)
			}
		} else {
			if readDepth == -1 {
				readDepth = n
			} else if n != readDepth {
				t.Errorf("%s: read operations do not share a middleware depth (%d vs %d)", key, n, readDepth)
			}
		}
	}

	if readDepth == -1 || writeDepth == -1 {
		t.Fatal("expected both read and write operations in the table")
	}
	if writeDepth != readDepth+1 {
		t.Errorf("write operations carry %d middlewares and reads carry %d: the table's Write flags "+
			"no longer line up with the requireWrite group", writeDepth, readDepth)
	}
}

// TestOpenAPIPublicCoversEveryRoute does the same for the sending API.
func TestOpenAPIPublicCoversEveryRoute(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	// Zero dependencies are enough: Handler() only assembles routes, and requiring
	// a live database to check a route list would make the check skippable exactly
	// when it matters.
	server, err := NewServer(Options{
		Ingest: &ingest.Service{}, Store: &store.Store{},
		Authenticator: &authn.Authenticator{}, Pool: &db.Pool{},
		Log: log, Version: "test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	router := routerOperations(t, server.Handler())
	table := tableOperations(t, SurfacePublic)
	skip := map[string]bool{"GET /healthz": true, "GET /readyz": true}

	for key := range router {
		if skip[key] {
			continue
		}
		if _, documented := table[key]; !documented {
			t.Errorf("the router serves %s but the OpenAPI route table does not list it", key)
		}
	}
	for key := range table {
		if !router[key] {
			t.Errorf("the OpenAPI route table lists %s but the router does not serve it", key)
		}
	}
}

// TestOpenAPIPathParametersAreDeclared catches a path with a placeholder the
// document never describes, which generates a TypeScript call signature missing
// an argument.
func TestOpenAPIPathParametersAreDeclared(t *testing.T) {
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		ops, err := operationsFor(surface)
		if err != nil {
			t.Fatalf("operationsFor: %v", err)
		}
		for _, op := range ops {
			declared := map[string]bool{}
			for _, p := range op.Params {
				if p.In != "path" {
					continue
				}
				if !p.Required {
					t.Errorf("%s %s: path parameter %q is not marked required", op.Method, op.Path, p.Name)
				}
				declared[p.Name] = true
			}

			// A placeholder is not always a whole segment: the custom-method routes
			// put it before a colon, as in "{id}:revoke".
			for _, name := range pathPlaceholders(op.Path) {
				if !declared[name] {
					t.Errorf("%s %s: the path contains {%s} but no parameter declares it",
						op.Method, op.Path, name)
				}
				delete(declared, name)
			}
			for name := range declared {
				t.Errorf("%s %s: declares path parameter %q that the path does not contain",
					op.Method, op.Path, name)
			}
		}
	}
}

// pathPlaceholders returns the {name} placeholders in a path, wherever they sit
// inside a segment.
func pathPlaceholders(path string) []string {
	var out []string
	for {
		open := strings.Index(path, "{")
		if open < 0 {
			return out
		}
		close := strings.Index(path[open:], "}")
		if close < 0 {
			return out
		}
		out = append(out, path[open+1:open+close])
		path = path[open+close+1:]
	}
}

// TestOpenAPIOperationIDsAreUnique protects the generated client: two operations
// sharing an id would collide into one function.
func TestOpenAPIOperationIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		ops, err := operationsFor(surface)
		if err != nil {
			t.Fatalf("operationsFor: %v", err)
		}
		for _, op := range ops {
			if op.ID == "" {
				t.Errorf("%s %s has no operationId", op.Method, op.Path)
				continue
			}
			if prior, dup := seen[op.ID]; dup {
				t.Errorf("operationId %q is used by both %s and %s %s", op.ID, prior, op.Method, op.Path)
			}
			seen[op.ID] = op.Method + " " + op.Path
		}
	}
}

// TestOpenAPICustomTypesAreDeclared is the guard the addressList case earned.
//
// A type with its own UnmarshalJSON accepts something its Go shape does not show.
// addressList is a []string that also accepts a bare string; described from
// reflection alone, the generated TypeScript would reject a payload the API
// accepts, and the operator would be told their own working request is invalid.
// Any future such type must declare a schema rather than inherit a wrong one.
func TestOpenAPICustomTypesAreDeclared(t *testing.T) {
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

	var walk func(t reflect.Type, path string, seen map[reflect.Type]bool)
	walk = func(typ reflect.Type, path string, seen map[reflect.Type]bool) {
		if seen[typ] {
			return
		}
		seen[typ] = true

		if _, declared := customSchemas[typ]; declared {
			return
		}
		if typ.Implements(unmarshaler) || reflect.PointerTo(typ).Implements(unmarshaler) {
			t.Errorf("%s (%s) has a custom UnmarshalJSON but no entry in customSchemas: "+
				"reflection cannot see what it accepts", typ, path)
			return
		}

		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(typ.Elem(), path, seen)
		case reflect.Map:
			walk(typ.Elem(), path, seen)
		case reflect.Struct:
			for i := range typ.NumField() {
				field := typ.Field(i)
				if !field.IsExported() || field.Tag.Get("json") == "-" {
					continue
				}
				walk(field.Type, path+"."+field.Name, seen)
			}
		}
	}

	seen := map[reflect.Type]bool{}
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		ops, err := operationsFor(surface)
		if err != nil {
			t.Fatalf("operationsFor: %v", err)
		}
		for _, op := range ops {
			for _, body := range []any{op.Request, op.Response} {
				if body == nil {
					continue
				}
				typ := reflect.TypeOf(body)
				walk(typ, typ.Name(), seen)
			}
		}
	}
}

// TestOpenAPIResponsesCarryNoSecret is a security assertion, not a documentation
// one.
//
// It was verified once by hand with curl. Made permanent here it becomes a fact
// about the API rather than a note about one afternoon: a field named for a
// secret cannot appear in a response schema without this failing. The single
// deliberate exception is the create-credential response, which shows the secret
// once and never again.
func TestOpenAPIResponsesCarryNoSecret(t *testing.T) {
	forbidden := []string{
		"password", "secret", "sealed", "fingerprint", "pepper", "hmac",
		"token", "key", "body", "html", "raw", "payload", "eml",
	}
	// The show-once response, whose whole purpose is to carry it.
	allowed := map[string]bool{"CreatedCredential.secret": true}

	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		doc := generatedDocument(t, surface)
		schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

		responseSchemas := responseSchemaNames(t, doc)
		names := make([]string, 0, len(responseSchemas))
		for name := range responseSchemas {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			schema, _ := schemas[name].(map[string]any)
			props, _ := schema["properties"].(map[string]any)
			for field := range props {
				for _, bad := range forbidden {
					if !strings.Contains(strings.ToLower(field), bad) {
						continue
					}
					if allowed[name+"."+field] {
						continue
					}
					// has_password says whether one is stored, which is all the UI
					// needs to choose between "set" and "rotate".
					if field == "has_password" {
						continue
					}
					t.Errorf("%s: response schema %s exposes a field named %q, which contains %q",
						surface, name, field, bad)
				}
			}
		}
	}
}

// responseSchemaNames returns every schema reachable from a response body,
// following $refs so a nested type is covered too.
func responseSchemaNames(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()

	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)
	out := map[string]bool{}

	var follow func(node any)
	follow = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				name := strings.TrimPrefix(ref, "#/components/schemas/")
				if !out[name] {
					out[name] = true
					follow(schemas[name])
				}
				return
			}
			for _, child := range v {
				follow(child)
			}
		case []any:
			for _, child := range v {
				follow(child)
			}
		}
	}

	paths, _ := doc["paths"].(map[string]any)
	for _, item := range paths {
		operations, _ := item.(map[string]any)
		for _, op := range operations {
			fields, _ := op.(map[string]any)
			follow(fields["responses"])
		}
	}
	return out
}

// TestOpenAPIRequiredFieldsExistInTheStruct catches the table naming a field the
// struct does not have, which is what happens when a request type is refactored
// and the document is not.
func TestOpenAPIRequiredFieldsExistInTheStruct(t *testing.T) {
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		ops, err := operationsFor(surface)
		if err != nil {
			t.Fatalf("operationsFor: %v", err)
		}
		for _, op := range ops {
			if len(op.RequiredFields) == 0 {
				continue
			}
			tags := map[string]bool{}
			typ := reflect.TypeOf(op.Request)
			for i := range typ.NumField() {
				name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					tags[name] = true
				}
			}
			for _, field := range op.RequiredFields {
				if !tags[field] {
					t.Errorf("%s %s: RequiredFields names %q, which %s does not have",
						op.Method, op.Path, field, typ)
				}
			}
		}
	}
}

// TestOpenAPIIsDeterministic guarantees the committed document only changes when
// the API does. Without it, map iteration order would produce a diff on every
// run and CI's comparison would be noise nobody reads.
func TestOpenAPIIsDeterministic(t *testing.T) {
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		first, err := OpenAPI(surface, "test")
		if err != nil {
			t.Fatalf("OpenAPI: %v", err)
		}
		for range 8 {
			again, err := OpenAPI(surface, "test")
			if err != nil {
				t.Fatalf("OpenAPI: %v", err)
			}
			if string(again) != string(first) {
				t.Fatalf("%s: two renderings of the same API differ", surface)
			}
		}
	}
}

// TestOpenAPIEveryOperationDocumentsAuthFailure asserts the document never
// suggests an endpoint might be reachable without a credential. There is no
// anonymous access to either surface under any condition.
func TestOpenAPIEveryOperationDocumentsAuthFailure(t *testing.T) {
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		doc := generatedDocument(t, surface)
		if _, ok := doc["security"]; !ok {
			t.Errorf("%s: the document declares no security requirement", surface)
		}
		paths, _ := doc["paths"].(map[string]any)
		for path, item := range paths {
			operations, _ := item.(map[string]any)
			for method, op := range operations {
				fields, _ := op.(map[string]any)
				responses, _ := fields["responses"].(map[string]any)
				if _, ok := responses["401"]; !ok {
					t.Errorf("%s: %s %s documents no 401", surface, strings.ToUpper(method), path)
				}
			}
		}
	}
}

// TestOpenAPISchemasAreAllReferenced catches a component nothing points at, which
// means either a dead entry or a response the table forgot to wire up.
func TestOpenAPISchemasAreAllReferenced(t *testing.T) {
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		doc := generatedDocument(t, surface)
		schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

		referenced := map[string]bool{}
		var follow func(node any)
		follow = func(node any) {
			switch v := node.(type) {
			case map[string]any:
				if ref, ok := v["$ref"].(string); ok {
					name := strings.TrimPrefix(ref, "#/components/schemas/")
					if !referenced[name] {
						referenced[name] = true
						follow(schemas[name])
					}
					return
				}
				for _, child := range v {
					follow(child)
				}
			case []any:
				for _, child := range v {
					follow(child)
				}
			}
		}
		follow(doc["paths"])

		for name := range schemas {
			if !referenced[name] {
				t.Errorf("%s: schema %s is defined but never referenced", surface, name)
			}
		}
	}
}

func generatedDocument(t *testing.T, surface Surface) map[string]any {
	t.Helper()

	raw, err := OpenAPI(surface, "test")
	if err != nil {
		t.Fatalf("OpenAPI(%s): %v", surface, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the generated document is not valid JSON: %v", err)
	}
	return doc
}

// TestOpenAPIRejectsAnUnknownSurface keeps the subcommand's error honest.
func TestOpenAPIRejectsAnUnknownSurface(t *testing.T) {
	if _, err := OpenAPI(Surface("everything"), "test"); err == nil {
		t.Fatal("OpenAPI accepted an unknown surface")
	}
}

// TestOpenAPIRequestSchemaConflictsAreReported covers the guard rails in the
// builder itself, which are the ones a future contributor will meet.
func TestOpenAPIRequestSchemaConflictsAreReported(t *testing.T) {
	t.Run("same name, different type", func(t *testing.T) {
		b := newBuilder()
		if _, err := b.requestRef("Thing", reflect.TypeOf(backendRequest{}), nil); err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err := b.requestRef("Thing", reflect.TypeOf(domainRequest{}), nil)
		if err == nil {
			t.Fatal("one schema name was accepted for two types")
		}
	})

	t.Run("same name, different required list", func(t *testing.T) {
		b := newBuilder()
		if _, err := b.requestRef("Thing", reflect.TypeOf(backendRequest{}), []string{"name"}); err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err := b.requestRef("Thing", reflect.TypeOf(backendRequest{}), []string{"host"})
		if err == nil {
			t.Fatal("one schema name was accepted with two required lists")
		}
	})

	t.Run("required field the struct lacks", func(t *testing.T) {
		b := newBuilder()
		_, err := b.requestRef("Thing", reflect.TypeOf(backendRequest{}), []string{"nonesuch"})
		if err == nil {
			t.Fatal("a required field absent from the struct was accepted")
		}
		if !strings.Contains(err.Error(), "nonesuch") {
			t.Errorf("the error does not name the field: %v", err)
		}
	})

	t.Run("a type used as both a request and a response", func(t *testing.T) {
		b := newBuilder()
		if _, err := b.ref(reflect.TypeOf(backendResponse{}), kindResponse); err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err := b.ref(reflect.TypeOf(backendResponse{}), kindRequest)
		if err == nil {
			t.Fatal("a response type was accepted as a request body")
		}
	})

	t.Run("an unregistered type", func(t *testing.T) {
		b := newBuilder()
		type stranger struct {
			Field string `json:"field"`
		}
		_, err := b.ref(reflect.TypeOf(stranger{}), kindResponse)
		if err == nil {
			t.Fatal("an unregistered type was accepted")
		}
	})
}

func newBuilder() *schemaBuilder {
	return &schemaBuilder{
		schemas:       map[string]any{},
		kinds:         map[string]schemaKind{},
		requestOrigin: map[string]requestProvenance{},
	}
}

// TestOpenAPIPatchSchemasRequireNothing pins the distinction that forced the
// per-operation schema names. A patch that demanded every field would make the
// frontend resend values it never showed the operator.
func TestOpenAPIPatchSchemasRequireNothing(t *testing.T) {
	doc := generatedDocument(t, SurfaceAdmin)
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

	for _, name := range []string{"BackendPatch", "DomainPatch", "CredentialPatch"} {
		schema, ok := schemas[name].(map[string]any)
		if !ok {
			t.Errorf("schema %s is missing", name)
			continue
		}
		if required, present := schema["required"]; present {
			t.Errorf("%s declares required fields %v: a patch changes only what it mentions",
				name, required)
		}
	}

	input, _ := schemas["BackendInput"].(map[string]any)
	required, _ := input["required"].([]any)
	if len(required) == 0 {
		t.Error("BackendInput requires nothing, so a create could omit the host it needs")
	}
}

// TestOpenAPIListSchemasSharePagination is a small consistency check: every list
// response is the same shape, so the frontend can page any of them with one
// helper instead of six.
func TestOpenAPIListSchemasSharePagination(t *testing.T) {
	doc := generatedDocument(t, SurfaceAdmin)
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

	for name, schema := range schemas {
		if !strings.HasSuffix(name, "List") {
			continue
		}
		props, _ := schema.(map[string]any)["properties"].(map[string]any)
		for _, field := range []string{"data", "next_cursor"} {
			if _, ok := props[field]; !ok {
				t.Errorf("%s has no %q", name, field)
			}
		}
		data, _ := props["data"].(map[string]any)
		if data["type"] != "array" {
			t.Errorf("%s.data is %v, want an array", name, data["type"])
		}
	}
}

func init() {
	// Fail loudly at test start if the two documents cannot be produced at all,
	// so a broken table reports itself once rather than through twelve tests.
	for _, surface := range []Surface{SurfaceAdmin, SurfacePublic} {
		if _, err := OpenAPI(surface, "init"); err != nil {
			panic(fmt.Sprintf("the %s OpenAPI document cannot be generated: %v", surface, err))
		}
	}
}

// TestEveryWriteOperationRefusesAViewer is the behavioural counterpart to
// TestOpenAPIWriteFlagsMatchTheRouter.
//
// That one compares the table against the router's shape, which is indirect. This
// one walks the table and calls every operation marked Write with a read-only
// token, asserting each is refused. It is the guarantee the frontend relies on
// when it renders controls from x-relais-requires-write, and the guarantee a
// viewer relies on to be unable to change anything.
//
// It runs against the real database because that is the only way to distinguish
// "refused because the role is wrong" from "refused because nothing exists".
func TestEveryWriteOperationRefusesAViewer(t *testing.T) {
	fixture := newAdminFixture(t)
	token := fixture.viewerToken()

	// A syntactically valid id that matches nothing. A viewer must be refused
	// before the store is ever consulted, so the row need not exist: a 404 here
	// would mean the role check ran too late.
	const absent = "00000000-0000-4000-8000-000000000000"

	// Bodies good enough to get past decoding. If a write ever answered 422 rather
	// than 403, that would mean the payload was parsed before the role was checked.
	bodies := map[string]string{
		"POST":  `{"name":"x","host":"h","port":25,"tls_mode":"none","patterns":["a@b.test"],"type":"api_key","backend_id":"` + absent + `","pattern":"a@b.test","address":"a@b.test"}`,
		"PATCH": `{"name":"x"}`,
	}

	ops, err := operationsFor(SurfaceAdmin)
	if err != nil {
		t.Fatalf("operationsFor: %v", err)
	}

	writes := 0
	for _, op := range ops {
		if !op.Write {
			continue
		}
		writes++

		path := op.Path
		for _, name := range pathPlaceholders(path) {
			path = strings.Replace(path, "{"+name+"}", absent, 1)
		}

		t.Run(op.ID, func(t *testing.T) {
			response := fixture.do(op.Method, path, token, bodies[op.Method])
			if response.Code != http.StatusForbidden {
				t.Errorf("%s %s: a viewer got %d, want 403\n%s",
					op.Method, path, response.Code, response.Body.String())
			}
		})
	}

	if writes == 0 {
		t.Fatal("no write operations were exercised, so this test proved nothing")
	}
	t.Logf("%d write operations refused a viewer", writes)
}

// TestEveryOperationRefusesNoToken pins the rule that has no exception: nothing on
// this surface answers without a credential.
func TestEveryOperationRefusesNoToken(t *testing.T) {
	fixture := newAdminFixture(t)

	ops, err := operationsFor(SurfaceAdmin)
	if err != nil {
		t.Fatalf("operationsFor: %v", err)
	}
	const absent = "00000000-0000-4000-8000-000000000000"

	for _, op := range ops {
		path := op.Path
		for _, name := range pathPlaceholders(path) {
			path = strings.Replace(path, "{"+name+"}", absent, 1)
		}
		response := fixture.do(op.Method, path, "", `{}`)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: an unauthenticated request got %d, want 401",
				op.Method, path, response.Code)
		}
	}
}

// TestErrorResponsesMatchTheDocumentedSchema is the guard the error envelope earned.
//
// Every other test in this file compares names and shapes derived from the same Go
// types, so all of them agreed with each other while the document described an error
// shape the server never sent: `writeError` wraps its body as {"error": {...}} and
// the table named the inner type. The generated TypeScript then read `code` off the
// envelope, found nothing, and every API error reached the operator as a bare status
// code. Nothing failed — the drift was between the document and the wire, and no
// test looked there.
//
// This one sends real requests, takes the bodies the server actually produces, and
// checks them against the documented schema.
func TestErrorResponsesMatchTheDocumentedSchema(t *testing.T) {
	fixture := newAdminFixture(t)
	token := fixture.adminToken()
	const absent = "00000000-0000-4000-8000-000000000000"

	// One response per status the document claims to describe.
	cases := []struct {
		name   string
		method string
		path   string
		token  string
		body   string
		want   int
	}{
		{"401 without a token", "GET", "/admin/v1/backends", "", "", 401},
		{"403 for a viewer", "POST", "/admin/v1/backends", fixture.viewerToken(),
			`{"name":"x","host":"h","port":25,"tls_mode":"none"}`, 403},
		{"404 for a missing row", "GET", "/admin/v1/credentials/" + absent, token, "", 404},
		{"422 for an invalid payload", "POST", "/admin/v1/backends", token,
			`{"name":"x","host":"h","port":70000,"tls_mode":"none"}`, 422},
		// 400, not 422: malformed JSON is a bad request, while a well-formed body that
		// is not acceptable is 422. The distinction is worth keeping — a client can
		// retry neither, but only one of them is a bug in its serialiser.
		{"400 for an unparseable body", "POST", "/admin/v1/backends", token, `{`, 400},
		{"404 for an unknown endpoint", "GET", "/admin/v1/nonesuch", token, "", 404},
	}

	properties := documentedErrorProperties(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := fixture.do(tc.method, tc.path, tc.token, tc.body)
			if response.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", response.Code, tc.want, response.Body.String())
			}

			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("the error body is not a JSON object: %v\n%s", err, response.Body.String())
			}

			for key := range body {
				if _, documented := properties[key]; !documented {
					t.Errorf("the response carries %q, which the documented Error schema does not have. "+
						"Body: %s", key, response.Body.String())
				}
			}
			for key := range properties {
				if _, present := body[key]; !present {
					t.Errorf("the documented Error schema has %q, which the response does not carry. "+
						"Body: %s", key, response.Body.String())
				}
			}

			// The part that actually broke: a client has to find a code and a message
			// where the document says they are.
			var envelope errorEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("the body does not decode as the documented envelope: %v", err)
			}
			if envelope.Error.Code == "" {
				t.Errorf("no code in %s", response.Body.String())
			}
			if envelope.Error.Message == "" {
				t.Errorf("no message in %s", response.Body.String())
			}
		})
	}
}

// documentedErrorProperties returns the top-level property names of the Error schema
// as published.
func documentedErrorProperties(t *testing.T) map[string]bool {
	t.Helper()

	doc := generatedDocument(t, SurfaceAdmin)
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)
	schema, ok := schemas["Error"].(map[string]any)
	if !ok {
		t.Fatal("the document has no Error schema")
	}
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		t.Fatal("the Error schema has no properties")
	}

	out := map[string]bool{}
	for name := range props {
		out[name] = true
	}
	return out
}
