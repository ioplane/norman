package clientbase

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"time"

	"github.com/rancher/norman/types"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLegacyMalformedCA(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "insecure"}[insecure], func(t *testing.T) {
			var gets, mutations atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					gets.Add(1)
				} else {
					mutations.Add(1)
				}
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			_, err := NewAPIClient(&ClientOpts{URL: server.URL, CACerts: "not a PEM certificate", Insecure: insecure})
			if err == nil {
				t.Error("malformed nonempty CA returned nil error")
			}
			if gets.Load() != 0 || mutations.Load() != 0 {
				t.Fatalf("GET=%d mutations=%d; want zero network", gets.Load(), mutations.Load())
			}
			t.Logf("GET=%d mutations=%d", gets.Load(), mutations.Load())
		})
	}
}

func contextSchema(w http.ResponseWriter, r *http.Request) {
	schemaURL := "http://" + r.Host
	if r.URL.Path != "/" {
		schemaURL += r.URL.Path
	}
	w.Header().Set("X-API-Schemas", schemaURL)
	fmt.Fprintf(w, `{"data":[{"id":"setting","resourceMethods":["GET","PUT","DELETE"],"collectionMethods":["POST"],"links":{"collection":"http://%s/settings"}}]}`, r.Host)
}

func TestContextMalformedCA(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		t.Run(fmt.Sprint(insecure), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer server.Close()
			_, err := NewAPIClientContext(context.Background(), &ClientOpts{URL: server.URL, CACerts: "not a PEM certificate", Insecure: insecure})
			if err == nil || requests.Load() != 0 {
				t.Fatalf("error=%v requests=%d", err, requests.Load())
			}
		})
	}
}

func TestContextPreCanceled(t *testing.T) {
	var gets, mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets.Add(1)
		} else {
			mutations.Add(1)
		}
		contextSchema(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewAPIClientContext(ctx, &ClientOpts{URL: server.URL})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("constructor: %v", err)
	}
	ops := &APIOperations{Opts: &ClientOpts{}, Client: server.Client(), Types: map[string]types.Schema{
		"setting": {ResourceMethods: []string{"GET", "PUT", "DELETE"}, CollectionMethods: []string{"POST"}, Links: map[string]string{COLLECTION: server.URL}},
	}}
	var out map[string]interface{}
	existing := &types.Resource{Links: map[string]string{SELF: server.URL}}
	for _, err := range []error{ops.DoGetContext(ctx, server.URL, nil, &out), ops.DoByIDContext(ctx, "setting", "name", &out), ops.DoCreateContext(ctx, "setting", nil, &out), ops.DoUpdateContext(ctx, "setting", existing, nil, &out), ops.DoResourceDeleteContext(ctx, "setting", existing)} {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operation: %v", err)
		}
	}
	if err := ops.DoResourceDeleteContext(context.Background(), "setting", nil); err == nil {
		t.Fatal("nil resource accepted for deletion")
	}
	if gets.Load() != 0 || mutations.Load() != 0 {
		t.Fatalf("GET=%d mutations=%d", gets.Load(), mutations.Load())
	}
	t.Logf("GET=%d mutations=%d", gets.Load(), mutations.Load())
}

func TestContextHTTPPhases(t *testing.T) {
	for _, operation := range []string{"constructor-first", "constructor-second", "get", "byid", "create", "update", "delete"} {
		for _, phase := range []string{"headers", "body", "error-body"} {
			t.Run(operation+"/"+phase, func(t *testing.T) {
				started := make(chan struct{})
				observed := make(chan struct{})
				release := make(chan struct{})
				var gets, mutations atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" {
						gets.Add(1)
					} else {
						mutations.Add(1)
					}
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("authorization missing")
						w.WriteHeader(401)
						return
					}
					blocked := r.URL.Path == "/blocked" || r.URL.Path == "/settings/name" || (operation == "create" && r.URL.Path == "/settings")
					if !blocked {
						if operation == "constructor-second" {
							w.Header().Set("X-API-Schemas", "http://"+r.Host+"/blocked")
							fmt.Fprint(w, `{}`)
						} else {
							contextSchema(w, r)
						}
						return
					}
					if phase != "headers" {
						w.Header().Set("X-API-Schemas", "http://"+r.Host+r.URL.Path)
						if phase == "error-body" {
							w.Header().Set("Location", "/unused")
							w.WriteHeader(http.StatusFound)
						}
						fmt.Fprint(w, `{`)
						w.(http.Flusher).Flush()
					}
					if phase != "error-body" {
						close(started)
					}
					<-r.Context().Done()
					close(observed)
				}))
				defer server.Close()
				budget := 3 * time.Second
				if phase == "body" {
					budget = 250 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(context.Background(), budget)
				defer cancel()
				opts := &ClientOpts{URL: server.URL, TokenKey: "test-token"}
				if phase == "error-body" {
					opts.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
						// The redirect hook establishes that Client.Do has received the status before cancellation.
						close(started)
						<-release
						return http.ErrUseLastResponse
					}}
				}
				var client APIBaseClient
				var err error
				if operation != "constructor-first" && operation != "constructor-second" {
					client, err = NewAPIClientContext(context.Background(), opts)
					if err != nil {
						t.Fatal(err)
					}
					defer client.Ops.Client.CloseIdleConnections()
				}
				done := make(chan error, 1)
				go func() {
					var out map[string]interface{}
					existing := &types.Resource{Links: map[string]string{SELF: server.URL + "/settings/name"}}
					switch operation {
					case "constructor-first":
						opts.URL = server.URL + "/blocked"
						_, err := NewAPIClientContext(ctx, opts)
						done <- err
					case "constructor-second":
						_, err := NewAPIClientContext(ctx, opts)
						done <- err
					case "get":
						done <- client.Ops.DoGetContext(ctx, server.URL+"/blocked", nil, &out)
					case "byid":
						done <- client.Ops.DoByIDContext(ctx, "setting", "name", &out)
					case "create":
						done <- client.Ops.DoCreateContext(ctx, "setting", map[string]string{"value": "new"}, &out)
					case "update":
						done <- client.Ops.DoUpdateContext(ctx, "setting", existing, map[string]string{"value": "new"}, &out)
					case "delete":
						done <- client.Ops.DoResourceDeleteContext(ctx, "setting", existing)
					}
				}()
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("blocked request not reached")
				}
				if phase != "body" {
					cancel()
				}
				if phase == "error-body" {
					close(release)
				}
				select {
				case err = <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("request did not return after cancel")
				}
				want := error(context.Canceled)
				if phase == "body" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("lost cancellation: %v", err)
				}
				if phase == "body" {
					var network *url.Error
					if errors.As(err, &network) {
						t.Fatalf("did not reach response-body read: %v", err)
					}
				}
				if phase == "error-body" {
					var apiErr *APIError
					if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
						t.Fatalf("lost API status: %v", err)
					}
				}
				select {
				case <-observed:
				case <-time.After(3 * time.Second):
					t.Fatal("server did not observe cancellation")
				}
				wantGET := int32(1)
				if operation != "constructor-first" {
					wantGET = 2
				}
				wantMutations := int32(0)
				if operation == "create" || operation == "update" || operation == "delete" {
					wantGET, wantMutations = 1, 1
				}
				if gets.Load() != wantGET || mutations.Load() != wantMutations {
					t.Fatalf("GET=%d want=%d mutations=%d want=%d", gets.Load(), wantGET, mutations.Load(), wantMutations)
				}
				t.Logf("GET=%d mutations=%d handler-canceled=true", gets.Load(), mutations.Load())
			})
		}
	}
}

func TestContextReuseAndIsolation(t *testing.T) {
	blocked, observed := make(chan struct{}), make(chan struct{})
	var gets, mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets.Add(1)
		} else {
			mutations.Add(1)
		}
		if r.URL.Path == "/blocked" {
			close(blocked)
			<-r.Context().Done()
			close(observed)
			return
		}
		if r.URL.Path == "/" {
			contextSchema(w, r)
			return
		}
		fmt.Fprint(w, `{"value":"ready"}`)
	}))
	defer server.Close()
	owner, ownerCancel := context.WithCancel(context.Background())
	client, err := NewAPIClientContext(owner, &ClientOpts{URL: server.URL, HTTPClient: &http.Client{}})
	ownerCancel()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Ops.Client.CloseIdleConnections()
	parent, parentCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer parentCancel()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		var out map[string]interface{}
		done <- client.Ops.DoGetContext(ctx, server.URL+"/blocked", nil, &out)
	}()
	select {
	case <-blocked:
	case <-parent.Done():
		t.Fatal("blocked operation not reached")
	}
	var out map[string]string
	if err := client.Ops.DoByIDContext(parent, "setting", "name", &out); err != nil || out["value"] != "ready" {
		t.Fatalf("independent operation: %v %v", out, err)
	}
	cancel()
	select {
	case err = <-done:
	case <-parent.Done():
		t.Fatal("blocked operation did not finish")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-observed:
	case <-parent.Done():
		t.Fatal("server missed cancellation")
	}
	if err := client.Ops.DoGet(server.URL+"/healthy", nil, &out); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 4 || mutations.Load() != 0 {
		t.Fatalf("GET=%d mutations=%d", gets.Load(), mutations.Load())
	}
	t.Logf("GET=%d mutations=%d reusable-after-owner-and-peer-cancel=true", gets.Load(), mutations.Load())
}

func TestContextErrorCausesAndLegacyStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			contextSchema(w, r)
		case "/truncated", "/status-truncated":
			w.Header().Set("Content-Length", "100")
			if r.URL.Path == "/status-truncated" {
				w.WriteHeader(503)
			}
			fmt.Fprint(w, `{`)
		case "/invalid":
			fmt.Fprint(w, `!`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"missing"}`)
		}
	}))
	defer server.Close()
	client, err := NewAPIClientContext(context.Background(), &ClientOpts{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Ops.Client.CloseIdleConnections()
	var out map[string]interface{}
	for _, path := range []string{"/truncated", "/status-truncated"} {
		err := client.Ops.DoGetContext(context.Background(), server.URL+path, nil, &out)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s lost read error: %v", path, err)
		}
		if path == "/status-truncated" {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 {
				t.Fatalf("lost status: %v", err)
			}
		}
	}
	err = client.Ops.DoGetContext(context.Background(), server.URL+"/invalid", nil, &out)
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("lost decode cause: %v", err)
	}
	for _, contextual := range []bool{false, true} {
		if contextual {
			err = client.Ops.DoGetContext(context.Background(), server.URL+"/missing", nil, &out)
		} else {
			err = client.Ops.DoGet(server.URL+"/missing", nil, &out)
		}
		apiErr, ok := err.(*APIError)
		if !ok || apiErr.StatusCode != 404 || apiErr.Body != "message=missing" {
			t.Fatalf("ordinary status changed: %T %v", err, err)
		}
	}
	err = client.Ops.DoGet(server.URL+"/status-truncated", nil, &out)
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Body != "Unreadable body." {
		t.Fatalf("legacy unreadable body changed: %T %v", err, err)
	}
	server.Close()
	err = client.Ops.DoGetContext(context.Background(), server.URL, nil, &out)
	var network *url.Error
	if !errors.As(err, &network) {
		t.Fatalf("lost network error: %v", err)
	}
}

func TestContextTLSAuthAndSchemaControls(t *testing.T) {
	var gets, mutations atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets.Add(1)
		} else {
			mutations.Add(1)
		}
		if r.Header.Get("Authorization") != "Basic dXNlcjpwYXNz" {
			t.Error("basic auth missing")
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["value"] != "new" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("mutation payload/headers changed: %v %v", payload, err)
			}
		}
		if (r.Method == http.MethodPut || r.Method == http.MethodDelete) && r.URL.Query().Get("source") != "kept" {
			t.Error("self URL query changed")
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("X-API-Schemas", "https://"+r.Host+"/schemas")
			fmt.Fprint(w, `{}`)
		case "/schemas":
			fmt.Fprintf(w, `{"data":[{"id":"setting","resourceMethods":["GET","PUT","DELETE"],"collectionMethods":["POST"],"links":{"collection":"https://%s/settings"}}]}`, r.Host)
		case "/redirect":
			http.Redirect(w, r, "/settings/name", 302)
		case "/settings/name":
			if r.Method == http.MethodDelete {
				if r.ContentLength != 0 {
					t.Error("DELETE request gained a body")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			fmt.Fprint(w, `{"value":"ok"}`)
		case "/settings":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"value":"created"}`)
		case "/filter":
			if r.URL.Query().Get("name") != "a b" {
				t.Error("filter missing")
			}
			fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	for _, contextual := range []bool{false, true} {
		for _, insecure := range []bool{false, true} {
			t.Run(fmt.Sprintf("context=%t/insecure=%t", contextual, insecure), func(t *testing.T) {
				opts := &ClientOpts{URL: server.URL, AccessKey: "user", SecretKey: "pass", CACerts: ca, Insecure: insecure, HTTPClient: &http.Client{}, Timeout: 2 * time.Second}
				var client APIBaseClient
				var err error
				if contextual {
					client, err = NewAPIClientContext(context.Background(), opts)
				} else {
					client, err = NewAPIClient(opts)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer client.Ops.Client.CloseIdleConnections()
				if client.Ops.Client != opts.HTTPClient || opts.HTTPClient.Timeout != opts.Timeout {
					t.Fatal("supplied client ownership changed")
				}
				var out map[string]string
				if err := client.Ops.DoByIDContext(context.Background(), "setting", "name", &out); err != nil || out["value"] != "ok" {
					t.Fatalf("ByID=%v %v", out, err)
				}
				if err := client.Ops.DoGetContext(context.Background(), server.URL+"/redirect", nil, &out); err != nil {
					t.Fatal(err)
				}
				if err := client.Ops.DoGetContext(context.Background(), server.URL+"/filter", &types.ListOpts{Filters: map[string]interface{}{"name": "a b"}}, &out); err != nil {
					t.Fatal(err)
				}
				updates := map[string]string{"value": "new"}
				existing := &types.Resource{Links: map[string]string{SELF: server.URL + "/settings/name?source=kept"}}
				if contextual {
					err = client.Ops.DoCreateContext(context.Background(), "setting", updates, &out)
				} else {
					err = client.Ops.DoCreate("setting", updates, &out)
				}
				if err != nil || out["value"] != "created" {
					t.Fatalf("Create=%v %v", out, err)
				}
				if contextual {
					err = client.Ops.DoUpdateContext(context.Background(), "setting", existing, updates, &out)
				} else {
					err = client.Ops.DoUpdate("setting", existing, updates, &out)
				}
				if err != nil || out["value"] != "ok" {
					t.Fatalf("Update=%v %v", out, err)
				}
				if contextual {
					err = client.Ops.DoResourceDeleteContext(context.Background(), "setting", existing)
				} else {
					err = client.Ops.DoResourceDelete("setting", existing)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := gets.Load()
				for _, schema := range []string{"unknown", "not-readable", "no-link"} {
					client.Types["not-readable"] = types.Schema{}
					client.Types["no-link"] = types.Schema{ResourceMethods: []string{"GET"}}
					if err := client.Ops.DoByIDContext(context.Background(), schema, "name", &out); err == nil {
						t.Fatalf("accepted schema %s", schema)
					}
					for _, err := range []error{client.Ops.DoCreateContext(context.Background(), schema, updates, &out), client.Ops.DoUpdateContext(context.Background(), schema, existing, updates, &out), client.Ops.DoResourceDeleteContext(context.Background(), schema, existing)} {
						if err == nil {
							t.Fatalf("mutation accepted schema %s", schema)
						}
					}
				}
				if before != gets.Load() {
					t.Fatal("schema validation reached network")
				}
			})
		}
	}
	if mutations.Load() != 12 {
		t.Fatalf("mutations=%d; want 12 legacy/contextual wire controls", mutations.Load())
	}
	t.Logf("GET=%d mutations=%d", gets.Load(), mutations.Load())
}

type cancelOnDecode struct{ cancel context.CancelFunc }

func (out *cancelOnDecode) UnmarshalJSON([]byte) error { out.cancel(); return nil }

func TestContextDecodeBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) }))
	defer server.Close()
	ops := &APIOperations{Opts: &ClientOpts{}, Client: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := ops.DoGetContext(ctx, server.URL, nil, &cancelOnDecode{cancel: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("decode-boundary cancellation: %v", err)
	}
}

func TestContextDeadline(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%t", body), func(t *testing.T) {
			started, observed := make(chan struct{}), make(chan struct{})
			var gets, mutations atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					gets.Add(1)
				} else {
					mutations.Add(1)
				}
				if body {
					fmt.Fprint(w, `{`)
					w.(http.Flusher).Flush()
				}
				close(started)
				<-r.Context().Done()
				close(observed)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			ops := &APIOperations{Opts: &ClientOpts{}, Client: server.Client()}
			var out map[string]interface{}
			err := ops.DoGetContext(ctx, server.URL, nil, &out)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline identity lost: %v", err)
			}
			if body {
				var network *url.Error
				if errors.As(err, &network) {
					t.Fatalf("did not reach response-body read: %v", err)
				}
			}
			select {
			case <-started:
			default:
				t.Fatal("deadline expired before handler entry")
			}
			select {
			case <-observed:
			case <-time.After(3 * time.Second):
				t.Fatal("handler missed deadline cancellation")
			}
			if gets.Load() != 1 || mutations.Load() != 0 {
				t.Fatalf("GET=%d mutations=%d", gets.Load(), mutations.Load())
			}
			t.Logf("GET=%d mutations=%d handler-canceled=true deadline-exceeded=true", gets.Load(), mutations.Load())
		})
	}
}

func TestContextTLSDefaults(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Schemas", "https://"+r.Host)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()
	for _, contextual := range []bool{false, true} {
		for _, insecure := range []bool{false, true} {
			t.Run(fmt.Sprintf("context=%t/insecure=%t", contextual, insecure), func(t *testing.T) {
				opts := &ClientOpts{URL: server.URL, Insecure: insecure}
				var client APIBaseClient
				var err error
				if contextual {
					client, err = NewAPIClientContext(context.Background(), opts)
				} else {
					client, err = NewAPIClient(opts)
				}
				if insecure {
					if err != nil {
						t.Fatal(err)
					}
					client.Ops.Client.CloseIdleConnections()
				} else {
					var unknown x509.UnknownAuthorityError
					if !errors.As(err, &unknown) {
						t.Fatalf("ordinary TLS did not reject untrusted CA: %v", err)
					}
				}
			})
		}
	}
}
